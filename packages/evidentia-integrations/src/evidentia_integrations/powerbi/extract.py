"""Power BI dataset row builders — pure functions transforming
Evidentia models into JSON-serializable rows for the Push Datasets
API.

Power BI Push Datasets accept rows as JSON arrays of objects (one
object per row, key=column, value=cell). The schema is declared
separately when the dataset is created (see :mod:`publish`).

Row-shape design notes:

- ISO 8601 timestamps with timezone offsets — Power BI's
  ``Datetime`` column type accepts these natively.
- Booleans go through as ``true`` / ``false`` JSON literals (Power
  BI ``Boolean`` column type).
- Lists are serialized as semicolon-joined strings (Power BI
  doesn't have a native list / array column type; users can split
  in Power Query if needed).
- ``None`` becomes JSON ``null``.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from enum import Enum
from typing import Any

from evidentia_core.audit import CollectionContext
from evidentia_core.models.gap import GapAnalysisReport
from evidentia_core.models.risk import RiskStatement


def _row_value(value: Any) -> Any:
    """Coerce a value into a Power-BI-friendly JSON-serializable form.

    v0.7.13 P3 closure of v0.7.8 LOW × 9 (items 5 + 7 + 8 — same root):

    - Item 5 (None handling in lists): list / tuple branch now skips
      None elements before joining, so a list like ``[None, "x",
      None]`` becomes ``"x"`` instead of ``"None;x;None"``.
    - Item 7+8 (Pydantic ``.value`` duck-typing collision): the
      previous ``hasattr(value, "value")`` check matched any object
      with a ``.value`` attribute, including Pydantic models that
      happen to expose a ``value`` field. Tightened to
      ``isinstance(value, Enum)`` so only true Enum instances
      take the ``.value`` branch.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, list | tuple):
        # Filter Nones to prevent "None" string leakage in joins.
        return ";".join(str(_row_value(v)) for v in value if v is not None)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, Enum):
        # Pydantic StrEnum / Enum — emit the string value not repr.
        return str(value.value)
    if isinstance(value, str | int | float):
        return value
    return str(value)


# Fixed schemas — used both to declare the dataset on creation
# (see :mod:`publish`) and to ensure each row payload covers every
# expected column.

GAP_DATASET_SCHEMA: list[dict[str, str]] = [
    {"name": "gap_id", "dataType": "String"},
    {"name": "organization", "dataType": "String"},
    {"name": "analyzed_at", "dataType": "Datetime"},
    {"name": "framework", "dataType": "String"},
    {"name": "control_id", "dataType": "String"},
    {"name": "control_title", "dataType": "String"},
    {"name": "control_family", "dataType": "String"},
    {"name": "gap_severity", "dataType": "String"},
    {"name": "implementation_status", "dataType": "String"},
    {"name": "status", "dataType": "String"},
    {"name": "priority_score", "dataType": "Double"},
    {"name": "implementation_effort", "dataType": "String"},
    {"name": "equivalent_controls", "dataType": "String"},
    {"name": "cross_framework_satisfies", "dataType": "String"},
    {"name": "jira_issue_key", "dataType": "String"},
    {"name": "servicenow_ticket_id", "dataType": "String"},
    {"name": "assigned_to", "dataType": "String"},
    {"name": "tags", "dataType": "String"},
    {"name": "created_at", "dataType": "Datetime"},
    {"name": "remediated_at", "dataType": "Datetime"},
    {"name": "gap_description", "dataType": "String"},
    {"name": "remediation_guidance", "dataType": "String"},
]


RISK_DATASET_SCHEMA: list[dict[str, str]] = [
    {"name": "risk_id", "dataType": "String"},
    {"name": "asset", "dataType": "String"},
    {"name": "threat_source", "dataType": "String"},
    {"name": "threat_event", "dataType": "String"},
    {"name": "vulnerability", "dataType": "String"},
    {"name": "predisposing_conditions", "dataType": "String"},
    {"name": "likelihood", "dataType": "String"},
    {"name": "likelihood_rationale", "dataType": "String"},
    {"name": "impact", "dataType": "String"},
    {"name": "impact_rationale", "dataType": "String"},
    {"name": "risk_level", "dataType": "String"},
    {"name": "recommended_controls", "dataType": "String"},
    {"name": "remediation_priority", "dataType": "Int64"},
    {"name": "estimated_remediation_effort", "dataType": "String"},
    {"name": "treatment", "dataType": "String"},
    {"name": "treatment_rationale", "dataType": "String"},
    {"name": "generated_by", "dataType": "String"},
    {"name": "generated_at", "dataType": "Datetime"},
    {"name": "model_used", "dataType": "String"},
    {"name": "temperature", "dataType": "Double"},
    {"name": "prompt_hash", "dataType": "String"},
    {"name": "run_id", "dataType": "String"},
    {"name": "risk_description", "dataType": "String"},
]


COLLECTION_RUN_DATASET_SCHEMA: list[dict[str, str]] = [
    {"name": "run_id", "dataType": "String"},
    {"name": "collector_id", "dataType": "String"},
    {"name": "collector_version", "dataType": "String"},
    {"name": "collected_at", "dataType": "Datetime"},
    {"name": "credential_identity", "dataType": "String"},
    {"name": "source_system_id", "dataType": "String"},
    {"name": "filter_applied", "dataType": "String"},
    {"name": "evidentia_version", "dataType": "String"},
]


def build_gap_dataset_rows(
    report: GapAnalysisReport,
) -> list[dict[str, Any]]:
    """Build Power BI Push Datasets rows from a GapAnalysisReport."""
    rows: list[dict[str, Any]] = []
    org = report.organization
    analyzed_at = _row_value(report.analyzed_at)
    for gap in report.gaps:
        rows.append(
            {
                "gap_id": gap.id,
                "organization": org,
                "analyzed_at": analyzed_at,
                "framework": gap.framework,
                "control_id": gap.control_id,
                "control_title": gap.control_title,
                "control_family": _row_value(gap.control_family),
                "gap_severity": _row_value(gap.gap_severity),
                "implementation_status": gap.implementation_status,
                "status": _row_value(gap.status),
                "priority_score": gap.priority_score,
                "implementation_effort": _row_value(gap.implementation_effort),
                "equivalent_controls": _row_value(gap.equivalent_controls_in_inventory),
                "cross_framework_satisfies": _row_value(gap.cross_framework_value),
                "jira_issue_key": _row_value(gap.jira_issue_key),
                "servicenow_ticket_id": _row_value(gap.servicenow_ticket_id),
                "assigned_to": _row_value(gap.assigned_to),
                "tags": _row_value(gap.tags),
                "created_at": _row_value(gap.created_at),
                "remediated_at": _row_value(gap.remediated_at),
                "gap_description": gap.gap_description,
                "remediation_guidance": gap.remediation_guidance,
            }
        )
    return rows


def build_risk_dataset_rows(
    risks: Iterable[RiskStatement],
) -> list[dict[str, Any]]:
    """Build Power BI Push Datasets rows from RiskStatement objects."""
    rows: list[dict[str, Any]] = []
    for risk in risks:
        ctx = risk.generation_context
        rows.append(
            {
                "risk_id": risk.id,
                "asset": risk.asset,
                "threat_source": risk.threat_source,
                "threat_event": risk.threat_event,
                "vulnerability": risk.vulnerability,
                "predisposing_conditions": _row_value(risk.predisposing_conditions),
                "likelihood": _row_value(risk.likelihood),
                "likelihood_rationale": risk.likelihood_rationale,
                "impact": _row_value(risk.impact),
                "impact_rationale": risk.impact_rationale,
                "risk_level": _row_value(risk.risk_level),
                "recommended_controls": _row_value(risk.recommended_controls),
                "remediation_priority": risk.remediation_priority,
                "estimated_remediation_effort": _row_value(risk.estimated_remediation_effort),
                "treatment": _row_value(risk.treatment),
                "treatment_rationale": _row_value(risk.treatment_rationale),
                "generated_by": risk.generated_by,
                "generated_at": _row_value(risk.generated_at),
                "model_used": _row_value(risk.model_used),
                "temperature": (ctx.temperature if ctx else None),
                "prompt_hash": (_row_value(ctx.prompt_hash) if ctx else None),
                "run_id": (_row_value(ctx.run_id) if ctx else None),
                "risk_description": risk.risk_description,
            }
        )
    return rows


def build_collection_run_dataset_rows(
    contexts: Iterable[CollectionContext],
) -> list[dict[str, Any]]:
    """Build Power BI Push Datasets rows from CollectionContext objects."""
    rows: list[dict[str, Any]] = []
    for ctx in contexts:
        rows.append(
            {
                "run_id": ctx.run_id,
                "collector_id": ctx.collector_id,
                "collector_version": ctx.collector_version,
                "collected_at": _row_value(ctx.collected_at),
                "credential_identity": ctx.credential_identity,
                "source_system_id": ctx.source_system_id,
                "filter_applied": json.dumps(ctx.filter_applied, sort_keys=True, default=str),
                "evidentia_version": ctx.evidentia_version,
            }
        )
    return rows
