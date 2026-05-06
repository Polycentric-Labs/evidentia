"""OSCAL exporters for Evidentia models.

Maps Evidentia gap reports to OSCAL Assessment Results (AR) JSON.

OSCAL AR spec: https://pages.nist.gov/OSCAL/concepts/layer/assessment/assessment-results/

v0.7.0: optional evidence embedding. When a list of
:class:`SecurityFinding` objects is provided alongside the gap report,
each finding is:

1. Added to ``back-matter.resources[]`` as a standalone OSCAL resource
   with its canonical JSON base64-encoded in ``base64.value`` and a
   SHA-256 hash in ``rlinks[].hashes[]`` (both OSCAL-standard fields).
2. Cross-referenced from each matching observation via
   ``relevant-evidence[].href: "#<resource-uuid>"``. A finding matches
   an observation when they share a control ID.

The digest is computed from the finding's canonical JSON serialization
(``model_dump(mode="json")`` → ``json.dumps(sort_keys=True, separators=(",", ":"))``)
so :mod:`evidentia_core.oscal.verify` can recompute it deterministically
for a chain-of-custody integrity check.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from evidentia_core.models.gap import ControlGap, GapAnalysisReport
from evidentia_core.oscal.digest import digest_bytes, format_digest

if TYPE_CHECKING:
    from evidentia_core.models.finding import SecurityFinding
    from evidentia_core.models.risk import RiskStatement
    from evidentia_core.models.tprm import Vendor


# v0.7.0 namespace for Evidentia-specific OSCAL prop extensions. Downstream
# tools that don't recognize this namespace will ignore the props (per
# OSCAL's extension rules) rather than rejecting the document.
EVIDENTIA_OSCAL_NS = "https://evidentia.dev/oscal"


def gap_report_to_oscal_ar(
    report: GapAnalysisReport,
    *,
    findings: list[SecurityFinding] | None = None,
    blind_spots: list[dict[str, str]] | None = None,
    vendor_inventory: list[Vendor] | None = None,
    risk_statements_with_traces: list[RiskStatement] | None = None,
) -> dict[str, Any]:
    """Convert a Evidentia gap report to an OSCAL Assessment Results dict.

    Produces a minimal but valid OSCAL assessment-results structure with:

    - metadata (title, version, last-modified, parties — v0.7.9: vendors
      from the TPRM inventory land here as ``type=organization`` parties)
    - results (one result containing findings, observations)
    - findings (one per gap, with severity and remediation)
    - back-matter.resources (v0.7.0: one per :class:`SecurityFinding` with
      SHA-256 digest; v0.7.9: one per :class:`Vendor` with vendor metadata
      props + SHA-256 digest of the canonical vendor record)

    Parameters
    ----------
    report:
        The gap analysis result to export.
    findings:
        Optional collector output. When provided, each finding becomes
        a hashed OSCAL back-matter resource cross-referenced from
        observations sharing a control ID. Enables end-to-end evidence
        chain of custody: tampering with an embedded finding changes
        its hash and fails :func:`evidentia_core.oscal.verify.verify_ar_file`.
    blind_spots:
        Optional list of collector blind-spot disclosures (v0.7.0).
        Each entry must have ``id``, ``title``, and ``description`` keys
        (matching :data:`evidentia_collectors.aws.access_analyzer.BLIND_SPOTS`
        shape). Each becomes a back-matter resource with
        ``class="blind-spot"`` and Evidentia-namespaced props so auditors
        see the explicit limits of automated coverage inline alongside
        the AR. Auditor expectation: every collector documents what it
        does NOT cover, surfaced in the same artifact as the findings.
    vendor_inventory:
        Optional TPRM vendor inventory list (v0.7.9 P0.5). When provided:

        - Each :class:`evidentia_core.models.tprm.Vendor` is added to
          ``metadata.parties[]`` as ``type=organization`` with vendor
          metadata as Evidentia-namespaced props (criticality_tier,
          regulatory_classification, contract dates, next_review_due,
          residual_risk_score). Standard OSCAL party-discovery surface
          for trestle-conformance.
        - Each Vendor is ALSO added to ``back-matter.resources[]`` as a
          tamper-evident resource: canonical JSON in ``base64.value``,
          SHA-256 in ``rlinks[].hashes[]``. Same integrity model as
          the v0.7.0 finding-resource embedding, so vendor-record
          tampering is detected by the existing
          :func:`evidentia_core.oscal.verify.verify_ar_file` chain.
        - The vendor's party UUID and back-matter resource UUID both
          equal :attr:`Vendor.id` so cross-references resolve.

        OCC Bulletin 2013-29 + FRB SR 13-19 + FFIEC IT Examination
        Handbook Outsourcing booklet auditors expect a
        comprehensive third-party inventory in the assessment artifact.
        OSCAL AR + vendor-inventory back-matter satisfies that
        expectation in a tool-portable, integrity-protected format.

    The output is a Python dict ready to be serialized as OSCAL JSON.
    """
    now_iso = _now_iso()
    ar_uuid = str(uuid4())
    result_uuid = str(uuid4())

    # v0.7.0: build evidence resources first so observations can reference
    # them by UUID. One resource per finding; indexed by control_id for
    # cross-referencing below.
    resource_by_control: dict[str, list[dict[str, Any]]] = {}
    back_matter_resources: list[dict[str, Any]] = []
    if findings:
        for finding in findings:
            resource = _finding_to_oscal_resource(finding)
            back_matter_resources.append(resource)
            for control_id in finding.control_ids:
                resource_by_control.setdefault(control_id, []).append(resource)

    # v0.7.0: blind-spot disclosures. Standalone back-matter resources
    # (no observation cross-references — they're scope-limit declarations,
    # not findings). Auditor-grade transparency: every collector documents
    # what it does NOT cover, surfaced in the same artifact as the findings.
    if blind_spots:
        for bs in blind_spots:
            back_matter_resources.append(_blind_spot_to_oscal_resource(bs))

    # v0.7.9 P0.5: TPRM vendor inventory. Vendors land in BOTH
    # metadata.parties[] (standard OSCAL discovery surface) AND
    # back-matter.resources[] (Evidentia-style tamper-evident records).
    # The dual encoding lets trestle-conformant tools navigate vendors
    # via parties while operators get the integrity guarantees from the
    # back-matter resource hash.
    vendor_parties: list[dict[str, Any]] = []
    if vendor_inventory:
        for vendor in vendor_inventory:
            back_matter_resources.append(_vendor_to_oscal_resource(vendor))
            vendor_parties.append(_vendor_to_oscal_party(vendor))

    # v0.8.0 P0.2: Policy Reasoning Trace surfacing. When operators
    # pass risk statements that carry a reasoning_trace, each trace
    # lands as a back-matter resource so trestle-conformance round-
    # trips preserve the trace — auditors get the LLM's claim-by-
    # claim reasoning chain inline alongside the gap findings.
    if risk_statements_with_traces:
        for stmt in risk_statements_with_traces:
            if stmt.reasoning_trace is None:
                continue
            back_matter_resources.append(
                _reasoning_trace_to_oscal_resource(stmt)
            )

    findings_output = [_gap_to_finding(gap) for gap in report.gaps]
    observations = [_gap_to_observation(gap, resource_by_control) for gap in report.gaps]

    ar_doc: dict[str, Any] = {
        "assessment-results": {
            "uuid": ar_uuid,
            "metadata": {
                "title": f"Gap Analysis: {report.organization}",
                "last-modified": now_iso,
                "version": report.evidentia_version,
                "oscal-version": "1.1.2",
                "parties": [
                    {
                        "uuid": str(uuid4()),
                        "type": "organization",
                        "name": report.organization,
                    },
                    *vendor_parties,
                ],
                "props": [
                    {
                        "name": "frameworks-analyzed",
                        "value": ", ".join(report.frameworks_analyzed),
                    },
                    {
                        "name": "coverage-percentage",
                        "value": str(report.coverage_percentage),
                    },
                    {
                        "name": "total-gaps",
                        "value": str(report.total_gaps),
                    },
                    *(
                        [
                            {
                                "name": "vendor-inventory-count",
                                "ns": EVIDENTIA_OSCAL_NS,
                                "value": str(len(vendor_inventory)),
                                "class": "tprm",
                            }
                        ]
                        if vendor_inventory
                        else []
                    ),
                ],
            },
            "import-ap": {
                "href": "#assessment-plan-placeholder",
            },
            "results": [
                {
                    "uuid": result_uuid,
                    "title": "Evidentia Gap Analysis Result",
                    "description": (
                        f"Automated gap analysis of {report.organization} "
                        f"against {', '.join(report.frameworks_analyzed)}."
                    ),
                    "start": report.analyzed_at.isoformat(),
                    "end": report.analyzed_at.isoformat(),
                    "reviewed-controls": {
                        "control-selections": [
                            {
                                "description": (f"Controls from {fw}"),
                                "include-all": {},
                            }
                            for fw in report.frameworks_analyzed
                        ],
                    },
                    "observations": observations,
                    "findings": findings_output,
                }
            ],
        }
    }

    # OSCAL 1.1.2 allows an optional top-level ``back-matter`` alongside
    # ``results``. Only emit it when there are resources to attach —
    # empty arrays are valid OSCAL but add noise to the diff.
    if back_matter_resources:
        ar_doc["assessment-results"]["back-matter"] = {
            "resources": back_matter_resources,
        }

    return ar_doc


def _blind_spot_to_oscal_resource(bs: dict[str, str]) -> dict[str, Any]:
    """Convert a collector blind-spot disclosure to an OSCAL back-matter resource.

    Blind-spots are scope-limit declarations, not findings. They tell
    auditors what the automated collector explicitly does NOT cover, so
    that the gap-analysis result is honest about its boundaries.

    Required keys in ``bs``: ``id`` (stable identifier),
    ``title`` (human-readable summary), ``description`` (what's not
    covered + recommended supplementary control). Matches the shape of
    ``evidentia_collectors.aws.access_analyzer.BLIND_SPOTS``.
    """
    return {
        "uuid": str(uuid4()),
        "title": bs["title"],
        "description": bs["description"],
        "props": [
            {
                "name": "blind-spot-id",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": bs["id"],
                "class": "blind-spot",
            },
        ],
    }


def _finding_to_oscal_resource(finding: SecurityFinding) -> dict[str, Any]:
    """Convert a SecurityFinding to an OSCAL back-matter resource.

    The resource embeds:

    - ``base64.value`` — canonical JSON of the finding, base64-encoded.
      Makes the AR self-contained: no external files needed to verify.
    - ``rlinks[].hashes[]`` — SHA-256 of the *decoded* base64 payload.
      Standard OSCAL integrity mechanism.
    - ``props[]`` — Evidentia-namespaced metadata (source system,
      severity) so downstream filters can triage without decoding.
    """
    # Canonical JSON → same serialization the verifier re-computes from.
    canonical = _finding_canonical_json(finding)
    hex_digest = digest_bytes(canonical)

    # OSCAL resource UUID must be stable per-finding so reruns produce
    # reviewable diffs. Derive from finding.id (already a UUID v4).
    resource_uuid = finding.id

    severity_value = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)

    return {
        "uuid": resource_uuid,
        "title": finding.title,
        "description": finding.description,
        "props": [
            {
                "name": "source-system",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": finding.source_system,
            },
            {
                "name": "severity",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": severity_value,
            },
            {
                "name": "evidence-digest",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": format_digest(hex_digest),
                "class": "integrity",
            },
        ],
        # OSCAL rlinks[] with hashes[] is the standards-track integrity
        # mechanism. Tools that don't speak the Evidentia ns above will
        # still find the hash here. ``href: "#<uuid>"`` is a self-reference.
        "rlinks": [
            {
                "href": f"#{resource_uuid}",
                "media-type": "application/json",
                "hashes": [
                    {
                        "algorithm": "SHA-256",
                        "value": hex_digest,
                    }
                ],
            }
        ],
        "base64": {
            "filename": f"{finding.id}.json",
            "media-type": "application/json",
            "value": base64.b64encode(canonical).decode("ascii"),
        },
    }


def _finding_canonical_json(finding: SecurityFinding) -> bytes:
    """Serialize a SecurityFinding to deterministic canonical JSON bytes.

    Identical to :func:`evidentia_core.oscal.digest.digest_model`'s input
    transform — same sort_keys + separators. Verifier reuses this same
    function, so both sides of the hash agree bit-for-bit.
    """
    payload = finding.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _reasoning_trace_canonical_json(stmt: RiskStatement) -> bytes:
    """Serialize a RiskStatement's reasoning_trace to canonical JSON bytes.

    Pre-condition: stmt.reasoning_trace is not None. Caller must
    have filtered. Same sort_keys + separators contract as
    :func:`_finding_canonical_json` so the verifier path is
    symmetric.
    """
    if stmt.reasoning_trace is None:  # pragma: no cover — caller-filtered
        raise ValueError(
            "_reasoning_trace_canonical_json called on RiskStatement "
            "with no reasoning_trace"
        )
    payload = stmt.reasoning_trace.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _reasoning_trace_to_oscal_resource(stmt: RiskStatement) -> dict[str, Any]:
    """Convert a RiskStatement's reasoning_trace to an OSCAL back-matter resource.

    The resource embeds the trace's canonical JSON in
    ``base64.value`` + a SHA-256 hash in ``rlinks[].hashes[]`` —
    same tamper-evident pattern as v0.7.0 finding resources +
    v0.7.9 vendor resources. Auditors verifying the AR re-derive
    the hash from the canonical bytes; tampering with the trace
    after emit fails verification.

    Resource UUID derives from the RiskStatement.id so re-emits
    of the same trace produce reviewable diffs (only the
    canonical bytes + hash change if the trace was modified).
    """
    canonical = _reasoning_trace_canonical_json(stmt)
    hex_digest = digest_bytes(canonical)
    trace = stmt.reasoning_trace
    # v0.8.1 F-V08-CR-8: replace ``assert`` with explicit
    # ValueError so the invariant survives PYTHONOPTIMIZE=1
    # / -O deployments (where asserts are stripped).
    if trace is None:  # caller-filtered; defensive
        raise ValueError(
            "_reasoning_trace_to_oscal_resource called on "
            "RiskStatement with no reasoning_trace; caller must "
            "filter via `if stmt.reasoning_trace is not None`"
        )
    return {
        "uuid": stmt.id,
        "title": (
            f"Reasoning trace for risk statement "
            f"{stmt.source_gap_id or stmt.id}"
        ),
        "description": (
            f"Policy Reasoning Trace per arXiv 2509.23291 — "
            f"{len(trace.claims)} claim(s); overall confidence "
            f"{trace.overall_confidence:.4f}."
        ),
        "props": [
            {
                "name": "reasoning-trace-source-statement",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": stmt.id,
                "class": "prt",
            },
            {
                "name": "reasoning-trace-claim-count",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": str(len(trace.claims)),
                "class": "prt",
            },
            {
                "name": "reasoning-trace-overall-confidence",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": f"{trace.overall_confidence:.4f}",
                "class": "prt",
            },
            {
                "name": "evidence-digest",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": format_digest(hex_digest),
                "class": "integrity",
            },
        ],
        "rlinks": [
            {
                "href": f"sha256:{hex_digest}",
                "hashes": [
                    {
                        "algorithm": "SHA-256",
                        "value": hex_digest,
                    },
                ],
            },
        ],
        "base64": {
            "filename": f"reasoning-trace-{stmt.id}.json",
            "media-type": "application/json",
            "value": base64.b64encode(canonical).decode("ascii"),
        },
    }


def _gap_to_finding(gap: ControlGap) -> dict[str, Any]:
    """Map a ControlGap to an OSCAL finding."""
    severity_value = gap.gap_severity.value if hasattr(gap.gap_severity, "value") else gap.gap_severity
    return {
        "uuid": gap.id,
        "title": f"{gap.control_id}: {gap.control_title}",
        "description": gap.gap_description,
        "target": {
            "type": "objective-id",
            "target-id": gap.control_id,
            "status": {
                "state": "not-satisfied",
                "reason": gap.implementation_status,
            },
        },
        "props": [
            {"name": "framework", "value": gap.framework},
            {"name": "severity", "value": severity_value},
            {"name": "priority-score", "value": str(gap.priority_score)},
            {
                "name": "implementation-effort",
                "value": (
                    gap.implementation_effort.value
                    if hasattr(gap.implementation_effort, "value")
                    else gap.implementation_effort
                ),
            },
            {
                "name": "cross-framework-count",
                "value": str(len(gap.cross_framework_value)),
            },
        ],
        "remarks": gap.remediation_guidance,
    }


def _gap_to_observation(
    gap: ControlGap,
    resource_by_control: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Map a ControlGap to an OSCAL observation.

    When ``resource_by_control`` is provided (v0.7.0+), any evidence
    resources matching this gap's control ID are attached as
    ``relevant-evidence[]`` cross-references. The observation's ``methods``
    becomes ``["TEST"]`` instead of ``["EXAMINE"]`` when evidence is
    attached, since automated findings are closer to a test result
    than a manual examination.
    """
    observation: dict[str, Any] = {
        "uuid": str(uuid4()),
        "title": f"Observation: {gap.control_id}",
        "description": gap.gap_description,
        "methods": ["EXAMINE"],
        "types": ["finding"],
        "subjects": [
            {
                "subject-uuid": gap.id,
                "type": "component",
            }
        ],
        "collected": _now_iso(),
        "props": [
            {"name": "framework", "value": gap.framework},
            {"name": "control-id", "value": gap.control_id},
        ],
    }

    if resource_by_control:
        linked_resources = resource_by_control.get(gap.control_id, [])
        if linked_resources:
            observation["methods"] = ["TEST"]
            observation["relevant-evidence"] = [
                {
                    "href": f"#{resource['uuid']}",
                    "description": resource["title"],
                }
                for resource in linked_resources
            ]

    return observation


def _vendor_canonical_json(vendor: Vendor) -> bytes:
    """Serialize a Vendor to deterministic canonical JSON bytes.

    Identical pattern to :func:`_finding_canonical_json` — same
    sort_keys + separators. Verifier reuses this so both sides of
    the hash agree bit-for-bit.
    """
    payload = vendor.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _vendor_to_oscal_party(vendor: Vendor) -> dict[str, Any]:
    """Convert a TPRM Vendor to an OSCAL ``metadata.parties[]`` entry.

    Surface goal: standard OSCAL discovery — auditors using trestle or
    other OSCAL tooling can list vendors via the ``parties[]`` field
    without needing to know about Evidentia's back-matter integrity model.

    The party type is always ``organization`` (vendors are organizational
    entities, not individuals). Vendor metadata lands in
    Evidentia-namespaced props so trestle-conformant tools ignore them
    while Evidentia-aware tooling consumes them.
    """
    props: list[dict[str, Any]] = [
        {
            "name": "vendor-id",
            "ns": EVIDENTIA_OSCAL_NS,
            "value": vendor.id,
            "class": "tprm",
        },
        {
            "name": "vendor-type",
            "ns": EVIDENTIA_OSCAL_NS,
            "value": (
                vendor.type.value
                if hasattr(vendor.type, "value")
                else str(vendor.type)
            ),
            "class": "tprm",
        },
        {
            "name": "criticality-tier",
            "ns": EVIDENTIA_OSCAL_NS,
            "value": (
                vendor.criticality_tier.value
                if hasattr(vendor.criticality_tier, "value")
                else str(vendor.criticality_tier)
            ),
            "class": "tprm",
        },
        {
            "name": "relationship-owner",
            "ns": EVIDENTIA_OSCAL_NS,
            "value": vendor.relationship_owner,
            "class": "tprm",
        },
        {
            "name": "contract-start-date",
            "ns": EVIDENTIA_OSCAL_NS,
            "value": vendor.contract_start_date.isoformat(),
            "class": "tprm",
        },
    ]
    # Optional fields surfaced as props only when present, so the AR
    # diff stays minimal when fields are unset.
    if vendor.contract_end_date is not None:
        props.append(
            {
                "name": "contract-end-date",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": vendor.contract_end_date.isoformat(),
                "class": "tprm",
            }
        )
    if vendor.last_due_diligence_review is not None:
        props.append(
            {
                "name": "last-due-diligence-review",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": vendor.last_due_diligence_review.isoformat(),
                "class": "tprm",
            }
        )
    if vendor.next_review_due is not None:
        props.append(
            {
                "name": "next-review-due",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": vendor.next_review_due.isoformat(),
                "class": "tprm",
            }
        )
    if vendor.region is not None:
        props.append(
            {
                "name": "region",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": vendor.region,
                "class": "tprm",
            }
        )
    if vendor.regulatory_classification:
        props.append(
            {
                "name": "regulatory-classification",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": ", ".join(
                    rc.value if hasattr(rc, "value") else str(rc)
                    for rc in vendor.regulatory_classification
                ),
                "class": "tprm",
            }
        )
    if vendor.residual_risk_score is not None:
        props.append(
            {
                "name": "residual-risk-score",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": str(vendor.residual_risk_score),
                "class": "tprm",
            }
        )
    if vendor.fourth_parties:
        props.append(
            {
                "name": "fourth-party-count",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": str(len(vendor.fourth_parties)),
                "class": "tprm",
            }
        )
    return {
        "uuid": vendor.id,
        "type": "organization",
        "name": vendor.name,
        "props": props,
    }


def _vendor_to_oscal_resource(vendor: Vendor) -> dict[str, Any]:
    """Convert a TPRM Vendor to an OSCAL ``back-matter.resources[]`` entry.

    Same integrity model as :func:`_finding_to_oscal_resource`:

    - ``base64.value`` — canonical JSON of the vendor record
    - ``rlinks[].hashes[]`` — SHA-256 of the canonical JSON
    - ``props[]`` — Evidentia-namespaced metadata so downstream filters
      can triage without decoding

    The resource UUID equals :attr:`Vendor.id` so it matches the
    party UUID emitted by :func:`_vendor_to_oscal_party`. Cross-references
    via ``href: "#<vendor-id>"`` resolve consistently.
    """
    canonical = _vendor_canonical_json(vendor)
    hex_digest = digest_bytes(canonical)
    criticality_value = (
        vendor.criticality_tier.value
        if hasattr(vendor.criticality_tier, "value")
        else str(vendor.criticality_tier)
    )
    type_value = (
        vendor.type.value
        if hasattr(vendor.type, "value")
        else str(vendor.type)
    )
    return {
        "uuid": vendor.id,
        "title": vendor.name,
        "description": vendor.notes
        or (
            f"TPRM vendor record for {vendor.name} "
            f"(criticality: {criticality_value}, type: {type_value})"
        ),
        "props": [
            {
                "name": "vendor-id",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": vendor.id,
                "class": "tprm",
            },
            {
                "name": "criticality-tier",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": criticality_value,
                "class": "tprm",
            },
            {
                "name": "evidence-digest",
                "ns": EVIDENTIA_OSCAL_NS,
                "value": format_digest(hex_digest),
                "class": "integrity",
            },
        ],
        "rlinks": [
            {
                "href": f"#{vendor.id}",
                "media-type": "application/json",
                "hashes": [
                    {
                        "algorithm": "SHA-256",
                        "value": hex_digest,
                    }
                ],
            }
        ],
        "base64": {
            "filename": f"vendor-{vendor.id}.json",
            "media-type": "application/json",
            "value": base64.b64encode(canonical).decode("ascii"),
        },
    }


def _now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    from datetime import UTC

    return datetime.now(UTC).isoformat()
