"""Tableau dataset builders — pure functions that transform
Evidentia models into Tableau-publishable CSV bytes.

The transformation logic lives here (not in :mod:`publish`) so it
can be unit-tested without a live Tableau server. The CSV format is
the lowest-common-denominator Tableau-publishable shape: every
modern Tableau Server / Cloud version accepts CSV data sources via
the publish-datasource REST endpoint.

Three datasets:

- **Gap inventory**: one row per gap (control_id, severity, status,
  remediation effort, ticket linkage, etc.).
- **Risk register**: one row per risk statement (NIST SP 800-30
  fields: threat, vulnerability, likelihood, impact, narrative).
- **Collection runs**: one row per evidence-collection run
  (CollectionContext metadata for audit trail dashboards).

Tableau-specific design notes:

- ISO 8601 UTC timestamps everywhere. Tableau's date parser handles
  ISO 8601 + timezone offsets natively.
- Boolean columns are emitted as the literal strings ``true`` /
  ``false`` (Tableau accepts both ``TRUE`` and ``true``).
- Lists (e.g. ``frameworks_satisfied``) are joined with semicolons
  — Tableau Prep can split them later if needed.
- Severity / status enums emit their string values verbatim.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable
from typing import Any

from evidentia_core.audit import CollectionContext
from evidentia_core.models.gap import GapAnalysisReport
from evidentia_core.models.risk import RiskStatement


def _serialize(value: Any) -> str:
    """Stringify a value for CSV output.

    - ``None`` → empty string (Tableau treats this as null)
    - bool → 'true' / 'false'
    - list / tuple → semicolon-joined repr of each element
    - everything else → ``str(value)``
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list | tuple):
        return ";".join(_serialize(v) for v in value)
    if hasattr(value, "isoformat"):
        # datetime / date — Tableau-friendly ISO 8601 UTC.
        return str(value.isoformat())
    if hasattr(value, "value") and not isinstance(value, str | int | float):
        # Pydantic Enum — emit the string value not the repr.
        return str(value.value)
    return str(value)


def build_gap_dataset_csv(report: GapAnalysisReport) -> bytes:
    """Build a CSV dataset of every gap in the report.

    Columns mirror the structure risk officers + audit committees
    expect on a compliance dashboard:

    - ``gap_id`` — stable Evidentia gap UUID
    - ``framework`` / ``control_id`` / ``control_title`` —
      what the gap references
    - ``control_family`` — FedRAMP / NIST control family for
      grouping
    - ``gap_severity`` — Critical / High / Medium / Low /
      Informational
    - ``implementation_status`` — missing / partial / planned /
      not_applicable
    - ``status`` — open / in_progress / remediated / accepted /
      not_applicable (lifecycle)
    - ``priority_score`` — sortable float
    - ``implementation_effort`` — small / medium / large / xlarge
    - ``equivalent_controls`` — comma-list of inventory controls
      that partially satisfy
    - ``cross_framework_satisfies`` — list of other frameworks
      this gap maps onto (efficiency dashboard input)
    - ``jira_issue_key`` / ``servicenow_ticket_id`` — outbound
      ticketing linkage
    - ``assigned_to`` / ``tags`` — workflow metadata
    - ``created_at`` / ``remediated_at`` — lifecycle timestamps
    - ``organization`` / ``analyzed_at`` — denormalized so the
      dashboard can filter by org or as-of date without a join
    - ``gap_description`` / ``remediation_guidance`` — narrative
      cells (last for column-width-friendly Tableau ordering)

    Returns: UTF-8 encoded CSV bytes ready to upload.
    """
    buf = io.StringIO()
    fieldnames = [
        "gap_id",
        "organization",
        "analyzed_at",
        "framework",
        "control_id",
        "control_title",
        "control_family",
        "gap_severity",
        "implementation_status",
        "status",
        "priority_score",
        "implementation_effort",
        "equivalent_controls",
        "cross_framework_satisfies",
        "jira_issue_key",
        "servicenow_ticket_id",
        "assigned_to",
        "tags",
        "created_at",
        "remediated_at",
        "gap_description",
        "remediation_guidance",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    org = report.organization
    analyzed_at = _serialize(report.analyzed_at)
    for gap in report.gaps:
        writer.writerow(
            {
                "gap_id": gap.id,
                "organization": org,
                "analyzed_at": analyzed_at,
                "framework": gap.framework,
                "control_id": gap.control_id,
                "control_title": gap.control_title,
                "control_family": _serialize(gap.control_family),
                "gap_severity": _serialize(gap.gap_severity),
                "implementation_status": gap.implementation_status,
                "status": _serialize(gap.status),
                "priority_score": gap.priority_score,
                "implementation_effort": _serialize(
                    gap.implementation_effort
                ),
                "equivalent_controls": _serialize(
                    gap.equivalent_controls_in_inventory
                ),
                "cross_framework_satisfies": _serialize(
                    gap.cross_framework_value
                ),
                "jira_issue_key": _serialize(gap.jira_issue_key),
                "servicenow_ticket_id": _serialize(
                    gap.servicenow_ticket_id
                ),
                "assigned_to": _serialize(gap.assigned_to),
                "tags": _serialize(gap.tags),
                "created_at": _serialize(gap.created_at),
                "remediated_at": _serialize(gap.remediated_at),
                "gap_description": gap.gap_description,
                "remediation_guidance": gap.remediation_guidance,
            }
        )
    return buf.getvalue().encode("utf-8")


def build_risk_dataset_csv(
    risks: Iterable[RiskStatement],
) -> bytes:
    """Build a CSV dataset of NIST SP 800-30 risk statements.

    Columns:

    - ``risk_id`` — stable UUID
    - ``asset`` / ``threat_source`` / ``threat_event`` /
      ``vulnerability`` — NIST SP 800-30 core fields
    - ``predisposing_conditions`` — semicolon-joined list
    - ``likelihood`` / ``likelihood_rationale`` —
      Very_Low/Low/Moderate/High/Very_High + free-text reason
    - ``impact`` / ``impact_rationale`` — same shape
    - ``risk_level`` — derived overall risk level
    - ``recommended_controls`` — semicolon-joined NIST 800-53
      control IDs
    - ``remediation_priority`` — int 1-5 (1 = most urgent)
    - ``estimated_remediation_effort`` — operator-facing string
    - ``treatment`` / ``treatment_rationale`` — disposition
    - ``generated_by`` / ``generated_at`` / ``model_used`` /
      ``temperature`` / ``prompt_hash`` / ``run_id`` —
      AI-provenance fields surfaced from GenerationContext for
      audit-trail dashboards
    - ``risk_description`` — full prose statement
    """
    buf = io.StringIO()
    fieldnames = [
        "risk_id",
        "asset",
        "threat_source",
        "threat_event",
        "vulnerability",
        "predisposing_conditions",
        "likelihood",
        "likelihood_rationale",
        "impact",
        "impact_rationale",
        "risk_level",
        "recommended_controls",
        "remediation_priority",
        "estimated_remediation_effort",
        "treatment",
        "treatment_rationale",
        "generated_by",
        "generated_at",
        "model_used",
        "temperature",
        "prompt_hash",
        "run_id",
        "risk_description",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for risk in risks:
        ctx = risk.generation_context
        writer.writerow(
            {
                "risk_id": risk.id,
                "asset": risk.asset,
                "threat_source": risk.threat_source,
                "threat_event": risk.threat_event,
                "vulnerability": risk.vulnerability,
                "predisposing_conditions": _serialize(
                    risk.predisposing_conditions
                ),
                "likelihood": _serialize(risk.likelihood),
                "likelihood_rationale": risk.likelihood_rationale,
                "impact": _serialize(risk.impact),
                "impact_rationale": risk.impact_rationale,
                "risk_level": _serialize(risk.risk_level),
                "recommended_controls": _serialize(
                    risk.recommended_controls
                ),
                "remediation_priority": risk.remediation_priority,
                "estimated_remediation_effort": _serialize(
                    risk.estimated_remediation_effort
                ),
                "treatment": _serialize(risk.treatment),
                "treatment_rationale": _serialize(
                    risk.treatment_rationale
                ),
                "generated_by": risk.generated_by,
                "generated_at": _serialize(risk.generated_at),
                "model_used": _serialize(risk.model_used),
                "temperature": (
                    _serialize(ctx.temperature) if ctx else ""
                ),
                "prompt_hash": (
                    _serialize(ctx.prompt_hash) if ctx else ""
                ),
                "run_id": _serialize(ctx.run_id) if ctx else "",
                "risk_description": risk.risk_description,
            }
        )
    return buf.getvalue().encode("utf-8")


def build_collection_run_dataset_csv(
    contexts: Iterable[CollectionContext],
) -> bytes:
    """Build a CSV dataset of CollectionContext audit-trail rows.

    One row per collection run + source-system pair. Useful for
    "did our evidence collection run on time?" dashboards.

    Columns:

    - ``run_id`` — collection-run ULID
    - ``collector_id`` — e.g. ``snowflake-scan``,
      ``databricks-scan``, ``sql-postgres-scan``
    - ``collector_version`` — semver of evidentia-collectors
    - ``collected_at`` — UTC timestamp
    - ``credential_identity`` — the principal (NOT the secret)
    - ``source_system_id`` — e.g. ``snowflake:ACME-PROD``
    - ``filter_applied`` — JSON-serialized filter dict (operators
      can split this later in Tableau Prep if needed)
    - ``evidentia_version`` — version of evidentia-core
    """
    import json

    buf = io.StringIO()
    fieldnames = [
        "run_id",
        "collector_id",
        "collector_version",
        "collected_at",
        "credential_identity",
        "source_system_id",
        "filter_applied",
        "evidentia_version",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for ctx in contexts:
        writer.writerow(
            {
                "run_id": ctx.run_id,
                "collector_id": ctx.collector_id,
                "collector_version": ctx.collector_version,
                "collected_at": _serialize(ctx.collected_at),
                "credential_identity": ctx.credential_identity,
                "source_system_id": ctx.source_system_id,
                "filter_applied": json.dumps(
                    ctx.filter_applied, sort_keys=True, default=str
                ),
                "evidentia_version": ctx.evidentia_version,
            }
        )
    return buf.getvalue().encode("utf-8")
