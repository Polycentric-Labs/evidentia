"""OSCAL Plan-of-Action-and-Milestones (POA&M) exporter (v0.9.0 P2).

Maps Evidentia POA&M items (ControlGap records with milestones) to
OSCAL Plan-of-Action-and-Milestones JSON per the OSCAL 1.1.2 schema.

OSCAL POA&M spec:
https://pages.nist.gov/OSCAL/concepts/layer/assessment/plan-of-action-and-milestones/

Top-level structure produced:

  plan-of-action-and-milestones:
    uuid                      # auto-generated per emit
    metadata:                 # standard OSCAL metadata block
      title
      version
      oscal-version: "1.2.1"  # v0.9.6 P4.2
      last-modified
      parties: [organization]
    import-ssp:               # required by schema; placeholder href
      href: "#system-security-plan-placeholder"
    observations: [...]       # one per POA&M item (control snapshot)
    risks: [...]              # one per POA&M item; carries milestones
                              # under risks[].remediations[].tracking-entries[]
    poam-items: [...]         # one per POA&M item; cross-references
                              # the matching risk via related-risks[]
    back-matter?:             # optional integrity-protected resources
      resources: [...]        # canonical-JSON+SHA-256 per POA&M record

The poam-item ↔ risk ↔ observation graph uses Evidentia's
``ControlGap.id`` (UUID) as the canonical identifier across all three
records, so trestle-conformance round-trips preserve the cross-
references without re-stamping.

Milestone-to-tracking-entry mapping:

Each :class:`evidentia_core.models.gap.Milestone` becomes one
``tracking-entry`` under the risk's remediation. The mapping is:

  - ``tracking-entry.uuid``         = ``milestone.id``
  - ``tracking-entry.title``        = first ~80 chars of description
  - ``tracking-entry.description``  = full milestone description
  - ``tracking-entry.start``        = ``milestone.created_at.isoformat()``
  - ``tracking-entry.date-time-stamp`` = ``milestone.updated_at.isoformat()``
  - ``tracking-entry.type``         = milestone-correction (OSCAL vocab)
  - ``tracking-entry.props``        = Evidentia-namespaced extensions
    carrying ``status`` + ``target_date`` + optional ``evidence_ref``

The Evidentia-namespaced props live under
``ns=https://evidentia.dev/oscal`` so trestle-conformance tools treat
them as opaque extension props (preserved through round-trip but not
interpreted) while Evidentia's own tooling can reconstruct the full
:class:`Milestone` from the prop set.

Auto-generation entry point:

  :func:`gap_report_to_oscal_poam` accepts a
  :class:`evidentia_core.models.gap.GapAnalysisReport` + an optional
  filter callable, applies the FedRAMP severity filter by default
  (CRITICAL + HIGH only), and emits one POA&M item per matching gap.

Integrity-protected back-matter resources mirror the v0.7.0 AR
exporter pattern: each POA&M record's canonical JSON is base64-
encoded in ``back-matter.resources[].base64.value`` with SHA-256 in
``rlinks[].hashes[]``. Tampering with the embedded record fails the
v0.7.0 chain-of-custody check.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from evidentia_core.models.common import enum_value as _enum_value
from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
    GapStatus,
    Milestone,
)
from evidentia_core.oscal._version import OSCAL_SCHEMA_VERSION
from evidentia_core.oscal.digest import digest_bytes, format_digest

EVIDENTIA_OSCAL_NS = "https://evidentia.dev/oscal"


# ── public surface ─────────────────────────────────────────────────


def gap_report_to_oscal_poam(
    report: GapAnalysisReport,
    *,
    severity_filter: Callable[[ControlGap], bool] | None = None,
    embed_back_matter: bool = True,
) -> dict[str, Any]:
    """Emit an OSCAL POA&M document from a gap-analysis report.

    Each :class:`ControlGap` becomes one POA&M item (with its
    associated risk + observation + tracking-entries-per-milestone).

    Parameters
    ----------
    report:
        The gap-analysis report to materialize.
    severity_filter:
        Optional predicate. When supplied, only gaps for which the
        predicate returns True become POA&M items. Default policy
        when ``None``: materialize CRITICAL + HIGH severity gaps
        (FedRAMP POA&M Template Completion Guide v3.0 §3.1
        auditor-default).
    embed_back_matter:
        When True (default), each POA&M item's canonical JSON is
        added to ``back-matter.resources[]`` with SHA-256 digest for
        chain-of-custody integrity. Tampering with an embedded
        record changes its hash and fails the v0.7.0
        :func:`evidentia_core.oscal.verify.verify_ar_file` chain.
        Set False to skip the back-matter block (smaller document;
        no integrity protection for the POA&M records themselves).
    """
    if severity_filter is None:
        severity_filter = _default_severity_filter

    selected_gaps = [g for g in report.gaps if severity_filter(g)]

    poam_uuid = str(uuid4())
    now_iso = report.analyzed_at.isoformat()

    poam_items: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    back_matter_resources: list[dict[str, Any]] = []

    for gap in selected_gaps:
        observation = _gap_to_observation(gap)
        risk = _gap_to_risk(gap)
        poam_item = _gap_to_poam_item(gap, risk["uuid"], observation["uuid"])
        observations.append(observation)
        risks.append(risk)
        poam_items.append(poam_item)
        if embed_back_matter:
            back_matter_resources.append(_poam_to_oscal_resource(gap))

    doc: dict[str, Any] = {
        "plan-of-action-and-milestones": {
            "uuid": poam_uuid,
            "metadata": {
                "title": f"POA&M: {report.organization}",
                "last-modified": now_iso,
                "version": report.evidentia_version,
                "oscal-version": OSCAL_SCHEMA_VERSION,
                "parties": [
                    {
                        "uuid": str(uuid4()),
                        "type": "organization",
                        "name": report.organization,
                    },
                ],
                "props": [
                    {
                        "name": "frameworks-analyzed",
                        "value": ", ".join(report.frameworks_analyzed),
                    },
                    {
                        "name": "poam-item-count",
                        "ns": EVIDENTIA_OSCAL_NS,
                        "value": str(len(poam_items)),
                        "class": "poam",
                    },
                    {
                        "name": "source-gap-report-uuid",
                        "ns": EVIDENTIA_OSCAL_NS,
                        "value": report.id,
                        "class": "poam",
                    },
                ],
            },
            "import-ssp": {
                "href": "#system-security-plan-placeholder",
            },
            "poam-items": poam_items,
        }
    }

    # OSCAL minItems=1: ``observations`` and ``risks`` are OPTIONAL arrays
    # that must be OMITTED when the severity filter selects no gaps, never
    # emitted as ``[]`` (trestle >= 5.0 enforces what the 4.x line
    # tolerated). ``poam-items`` is REQUIRED and stays unconditional: a
    # POA&M with nothing materialized failing schema validation is correct
    # signal, not a shape to paper over.
    if observations:
        doc["plan-of-action-and-milestones"]["observations"] = observations
    if risks:
        doc["plan-of-action-and-milestones"]["risks"] = risks

    if back_matter_resources:
        doc["plan-of-action-and-milestones"]["back-matter"] = {
            "resources": back_matter_resources,
        }

    return doc


# ── default severity filter ────────────────────────────────────────


def _default_severity_filter(gap: ControlGap) -> bool:
    """Return True for CRITICAL + HIGH severity gaps.

    Matches the FedRAMP POA&M Template Completion Guide v3.0 §3.1
    expectation: POA&M items track *material* findings; lower-
    severity gaps are documented in the SSP risk register without
    ceremony. Operators can override via the ``severity_filter``
    parameter on :func:`gap_report_to_oscal_poam`.
    """
    return gap.gap_severity in {GapSeverity.CRITICAL, GapSeverity.HIGH}


# ── per-gap mappers ────────────────────────────────────────────────


def _gap_to_observation(gap: ControlGap) -> dict[str, Any]:
    """Map a ControlGap to an OSCAL observation element.

    Observations are the "what we noticed" layer. Each observation
    references the underlying control_id via a relevant-evidence
    cross-reference + carries an Evidentia-namespaced
    ``framework-control-id`` prop for trestle interoperability.
    """
    return {
        "uuid": str(uuid4()),
        "title": f"Gap in {gap.framework}:{gap.control_id}",
        "description": gap.gap_description,
        "methods": ["EXAMINE"],  # OSCAL vocab — observation method
        "types": ["control-objective"],  # OSCAL vocab
        "collected": gap.created_at.isoformat(),
        "props": [
            {
                "name": "framework",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": gap.framework,
                "class": "poam",
            },
            {
                "name": "control-id",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": gap.control_id,
                "class": "poam",
            },
            {
                "name": "implementation-status",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": gap.implementation_status,
                "class": "poam",
            },
        ],
    }


def _gap_to_risk(gap: ControlGap) -> dict[str, Any]:
    """Map a ControlGap to an OSCAL risk element with milestone tracking.

    Milestones land under ``risk.remediations[0].tracking-entries[]``
    so OSCAL-conformant tools see the remediation timeline in the
    canonical spec location. Evidentia's own loader (when v0.9.0 P2
    ships an OSCAL POA&M importer; deferred to v0.9.1) reconstructs
    :class:`Milestone` records from the tracking-entry props.
    """
    remediation_uuid = str(uuid4())
    tracking_entries = [_milestone_to_tracking_entry(ms) for ms in gap.poam_milestones]

    risk: dict[str, Any] = {
        "uuid": gap.id,  # cross-references match by gap.id
        "title": f"Risk from {gap.framework}:{gap.control_id} gap",
        "description": gap.gap_description,
        "statement": gap.remediation_guidance,
        "status": _gap_status_to_risk_status(gap),
        "props": [
            {
                "name": "severity",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": _enum_value(gap.gap_severity),
                "class": "poam",
            },
            {
                "name": "implementation-effort",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": _enum_value(gap.implementation_effort),
                "class": "poam",
            },
            {
                "name": "priority-score",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": f"{gap.priority_score:.4f}",
                "class": "poam",
            },
        ],
    }

    remediation: dict[str, Any] = {
        "uuid": remediation_uuid,
        "lifecycle": "planned" if not tracking_entries else "in-progress",
        "title": f"Remediation for {gap.framework}:{gap.control_id}",
        "description": gap.remediation_guidance,
    }
    if tracking_entries:
        remediation["remediation-tracking"] = {
            "tracking-entries": tracking_entries,
        }
    risk["remediations"] = [remediation]

    return risk


def _gap_to_poam_item(
    gap: ControlGap,
    risk_uuid: str,
    observation_uuid: str,
) -> dict[str, Any]:
    """Map a ControlGap to an OSCAL poam-item.

    The poam-item cross-references the matching risk + observation
    by their UUIDs. The poam-item itself carries the auditor-visible
    summary (title + description); the risk + observation carry the
    detail.
    """
    return {
        "uuid": str(uuid4()),
        "title": f"{gap.framework}:{gap.control_id} remediation",
        "description": gap.gap_description,
        "props": [
            {
                "name": "severity",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": _enum_value(gap.gap_severity),
                "class": "poam",
            },
            {
                "name": "framework",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": gap.framework,
                "class": "poam",
            },
            {
                "name": "control-id",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": gap.control_id,
                "class": "poam",
            },
            {
                "name": "milestone-count",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": str(len(gap.poam_milestones)),
                "class": "poam",
            },
        ],
        "related-observations": [
            {"observation-uuid": observation_uuid},
        ],
        "related-risks": [
            {"risk-uuid": risk_uuid},
        ],
    }


def _milestone_to_tracking_entry(ms: Milestone) -> dict[str, Any]:
    """Map a Milestone to an OSCAL tracking-entry.

    Uses ``milestone.id`` as the tracking-entry UUID so a reverse
    importer can reconstruct the milestone identity without
    re-stamping.
    """
    title = ms.description[:80]
    if len(ms.description) > 80:
        title += "…"
    props = [
        {
            "name": "status",
            "ns": EVIDENTIA_OSCAL_NS,
            "value": _enum_value(ms.status),
            "class": "poam-milestone",
        },
        {
            "name": "target-date",
            "ns": EVIDENTIA_OSCAL_NS,
            "value": ms.target_date.isoformat(),
            "class": "poam-milestone",
        },
    ]
    if ms.evidence_ref:
        props.append(
            {
                "name": "evidence-ref",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": ms.evidence_ref,
                "class": "poam-milestone",
            }
        )
    return {
        "uuid": ms.id,
        "title": title,
        "description": ms.description,
        "start": ms.created_at.isoformat(),
        "date-time-stamp": ms.updated_at.isoformat(),
        "type": "milestone-correction",  # OSCAL controlled vocab
        "props": props,
    }


def _gap_status_to_risk_status(gap: ControlGap) -> str:
    """Map ControlGap.status to OSCAL risk status vocabulary.

    OSCAL risk-status enum: open / investigating / remediating /
    deviation-requested / deviation-approved / closed.
    """
    mapping: dict[str, str] = {
        GapStatus.OPEN.value: "open",
        GapStatus.IN_PROGRESS.value: "investigating",
        GapStatus.REMEDIATED.value: "closed",
        GapStatus.ACCEPTED.value: "deviation-approved",
        GapStatus.NOT_APPLICABLE.value: "deviation-approved",
    }
    return mapping.get(_enum_value(gap.status), "open")


def _poam_to_oscal_resource(gap: ControlGap) -> dict[str, Any]:
    """Build an OSCAL back-matter resource for integrity protection.

    Mirrors the v0.7.0 finding-resource embedding pattern: canonical
    JSON in ``base64.value`` + SHA-256 hash in ``rlinks[].hashes[]``.
    Tampering with the embedded record changes the hash and fails
    the v0.7.0 chain-of-custody check.
    """
    canonical = _poam_canonical_json(gap)
    digest_hex = format_digest(digest_bytes(canonical))
    return {
        "uuid": gap.id,  # match the risk uuid for cross-reference
        "title": f"POA&M record: {gap.framework}:{gap.control_id}",
        "description": (
            f"Canonical JSON of the Evidentia ControlGap record "
            f"for {gap.framework}:{gap.control_id}, with SHA-256 "
            f"for tamper-evidence."
        ),
        "props": [
            {
                "name": "evidentia-record-type",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": "poam-item",
                "class": "poam",
            },
        ],
        "rlinks": [
            {
                "href": f"#poam-{gap.id}",
                "media-type": "application/json",
                "hashes": [
                    {
                        "algorithm": "SHA-256",
                        "value": digest_hex,
                    }
                ],
            }
        ],
        "base64": {
            "filename": f"poam-{gap.id}.json",
            "media-type": "application/json",
            "value": base64.b64encode(canonical).decode("ascii"),
        },
    }


def _poam_canonical_json(gap: ControlGap) -> bytes:
    """Serialize a ControlGap as canonical JSON for digest computation.

    Uses ``sort_keys=True`` + minimal separators so the same record
    produces the same bytes (and the same hash) across Python
    sessions + Pydantic-model-version upgrades that don't change
    the JSON schema.
    """
    data = gap.model_dump(mode="json")
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


__all__ = [
    "EVIDENTIA_OSCAL_NS",
    "gap_report_to_oscal_poam",
]
