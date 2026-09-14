"""Build stable SCAP evidence from the private verified source derivation."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from uuid import NAMESPACE_URL, uuid5

from evidentia_core.models.evidence import EvidenceArtifact as CoreEvidenceArtifact

from ._contracts import (
    ArtifactWithoutId,
    AssertionActor,
    AssessmentProjection,
    CadenceProjection,
    CompletionProjection,
    NativeDocument,
    RunMetadata,
    ScapCollectionResult,
    ScapImportRequest,
    SourceBinding,
    StableCompletionAssertion,
)
from ._json import canonical_bytes, canonical_size
from ._limits import (
    ASSESSMENT_LIMIT,
    NATIVE_LIMIT,
    REMAINDER_LIMIT,
    RESULT_LIMIT,
    STABLE_CLAIM_LIMIT,
    Budget,
    ScapFailure,
    parse_utc,
    utc_text,
)

_ARTIFACT_NAMESPACE = uuid5(NAMESPACE_URL, "https://evidentiagrc.com/scap/evidence/v1")
_QUALIFICATION_ORDER = (
    "native_completion_absent",
    "native_completion_timezone_missing",
    "native_completion_precision_unsupported",
    "native_completion_range_unsupported",
    "native_completion_normalization_unsupported",
    "native_completion_future",
    "native_start_unresolved",
    "native_completion_before_start",
)
_DIAGNOSTICS = (
    ("source_authenticity_unverified", "Source authenticity was not verified."),
    ("source_population_not_established", "The source does not establish complete scanner population coverage."),
    ("complete_schema_validation_not_performed", "Complete schema validation was not performed."),
    ("platform_validation_not_performed", "OVAL platform validation was not performed."),
    (
        "findings_are_summary_only",
        "The finding summarizes one selected assessment; native outcomes are retained separately.",
    ),
    ("signature_unverified", "A source signature is present and was not verified."),
    ("partial_export_detail", "The declared OVAL export detail includes thin output."),
    ("uninterpreted_content_preserved", "Native content outside the interpreted core is preserved."),
    ("operator_completion_asserted", "Assessment completion is an explicit operator assertion."),
    ("native_completion_absent", "No native assessment completion time is available."),
    ("native_completion_timezone_missing", "The native completion time has no timezone."),
    ("native_completion_precision_unsupported", "The native completion precision cannot be represented exactly."),
    ("native_completion_range_unsupported", "The native completion time is outside the supported range."),
    (
        "native_completion_normalization_unsupported",
        "The native completion time cannot be normalized under the admitted policy.",
    ),
    ("native_completion_future", "The native completion is later than the import start."),
    ("native_start_unresolved", "The native assessment start cannot be compared exactly."),
    ("native_completion_before_start", "The native completion precedes the native assessment start."),
    ("no_selected_outcome_evidence", "The selected assessment contains no top-level outcome evidence."),
    ("selected_outcomes_not_evaluated", "The selected assessment contains only unevaluated top-level outcomes."),
)


def _completion(
    source: SourceBinding,
    assessment: AssessmentProjection,
    request: ScapImportRequest,
    actor: AssertionActor | None,
    imported_at: datetime,
    budget: Budget,
) -> CompletionProjection:
    claim = request.completion_assertion
    if claim is not None:
        if source.profile == "xccdf-1.2-results":
            raise ScapFailure("completion_assertion_not_permitted")
        if (
            claim.source_sha256 != source.sha256
            or claim.source_profile != source.profile
            or claim.assessment_index != request.assessment_index
        ):
            raise ScapFailure("completion_assertion_binding_mismatch")
        asserted_completion = parse_utc(claim.completed_at)
        if asserted_completion > imported_at:
            raise ScapFailure("completion_assertion_time_ineligible")
        if actor is None:
            raise ScapFailure()
        stable = {
            **claim.model_dump(),
            "normalized_utc": utc_text(asserted_completion),
            "basis": "operator_asserted",
            "actor": actor.model_dump(),
        }
        canonical_size(stable, STABLE_CLAIM_LIMIT, budget, publication=True)
        StableCompletionAssertion.model_validate(stable)
        return CompletionProjection.model_validate(
            {
                "state": "operator_qualified",
                "basis": "operator_asserted",
                "utc": utc_text(asserted_completion),
                "native_ref": None,
                "assertion": stable,
                "qualification_reasons": [],
            }
        )
    selected = assessment.selection.node_index
    native_end = next(
        (
            row
            for row in assessment.times
            if row.scope_node_index == selected
            and row.role == "assessment_completion"
            and row.scope == "selected_assessment"
        ),
        None,
    )
    native_start = next(
        (
            row
            for row in assessment.times
            if row.scope_node_index == selected
            and row.role == "assessment_start"
            and row.scope == "selected_assessment"
        ),
        None,
    )
    reasons: set[str] = set()
    completed = None
    if native_end is None:
        reasons.add("native_completion_absent")
    elif native_end.normalization.utc is None:
        reasons.add("native_completion_" + native_end.normalization.state)
    else:
        completed = parse_utc(native_end.normalization.utc, canonical=True)
        if completed > imported_at:
            reasons.add("native_completion_future")
    if native_start is not None:
        if native_start.normalization.utc is None:
            reasons.add("native_start_unresolved")
        elif completed is not None and completed < parse_utc(native_start.normalization.utc, canonical=True):
            reasons.add("native_completion_before_start")
    qualified = completed is not None and not reasons
    return CompletionProjection.model_validate(
        {
            "state": "native_qualified" if qualified else "unqualified",
            "basis": "native_reported" if qualified else "none",
            "utc": utc_text(completed) if qualified and completed is not None else None,
            "native_ref": None if native_end is None else native_end.value_ref.model_dump(),
            "assertion": None,
            "qualification_reasons": [reason for reason in _QUALIFICATION_ORDER if reason in reasons],
        }
    )


def _cadence(
    request: ScapImportRequest, assessment: AssessmentProjection, completion: CompletionProjection
) -> CadenceProjection:
    slug = request.cadence_slug
    reasons: list[str] = list(completion.qualification_reasons)
    if assessment.coverage.cadence_evidence == "empty":
        reasons.append("no_selected_outcome_evidence")
    elif assessment.coverage.cadence_evidence == "not_evaluated":
        reasons.append("selected_outcomes_not_evaluated")
    linked = slug is not None and not reasons
    return CadenceProjection.model_validate(
        {
            "state": "not_requested" if slug is None else "linked" if linked else "ineligible",
            "requested_slug": slug,
            "linked_slug": slug if linked else None,
            "reasons": reasons if slug is not None else [],
        }
    )


def _diagnostics(
    assessment: AssessmentProjection, completion: CompletionProjection, oval: bool
) -> list[dict[str, object]]:
    coverage = assessment.coverage
    codes = {
        "source_authenticity_unverified",
        "source_population_not_established",
        "complete_schema_validation_not_performed",
        "findings_are_summary_only",
    }
    if oval:
        codes.add("platform_validation_not_performed")
    if coverage.signature_node_indices:
        codes.add("signature_unverified")
    if coverage.native_export_detail in ("thin", "mixed"):
        codes.add("partial_export_detail")
    if coverage.uninterpreted_node_count:
        codes.add("uninterpreted_content_preserved")
    if completion.state == "operator_qualified":
        codes.add("operator_completion_asserted")
    codes.update(completion.qualification_reasons)
    if coverage.cadence_evidence == "empty":
        codes.add("no_selected_outcome_evidence")
    elif coverage.cadence_evidence == "not_evaluated":
        codes.add("selected_outcomes_not_evaluated")
    return [
        {"code": code, "severity": "advisory", "message": message, "node_index": None}
        for code, message in _DIAGNOSTICS
        if code in codes
    ]


def _artifact(
    source: SourceBinding,
    native: NativeDocument,
    assessment: AssessmentProjection,
    completion: CompletionProjection,
    cadence: CadenceProjection,
    budget: Budget,
) -> dict[str, object] | None:
    if completion.state == "unqualified":
        return None
    oval = source.profile != "xccdf-1.2-results"
    stable = {
        "basis": completion.basis,
        "utc": completion.utc,
        "native_ref": None if completion.native_ref is None else completion.native_ref.model_dump(),
        "assertion": None if completion.assertion is None else completion.assertion.model_dump(),
    }
    content = {
        "schema_version": "scap-evidence-v1",
        "source": source.model_dump(),
        "native_document": native.model_dump(),
        "assessment": assessment.model_dump(),
        "completion": stable,
    }
    canonical_size(content, RESULT_LIMIT, budget, publication=True)
    metadata: dict[str, object] = {
        "scap_contract": "scap-evidence-v1",
        "source_sha256": source.sha256,
        "source_profile": source.profile,
        "assessment_index": assessment.selection.assessment_index,
        "time_basis": completion.basis,
    }
    if cadence.linked_slug is not None:
        metadata["cadence_slug"] = cadence.linked_slug
    artifact: dict[str, object] = {
        "title": "Imported OVAL assessment" if oval else "Imported XCCDF assessment",
        "description": (
            "Native source observations with disclosed completion provenance; "
            "no authenticity, completeness or compliance conclusion."
        ),
        "evidence_type": "test_result",
        "source_system": "scap-oval" if oval else "scap-xccdf",
        "collected_at": completion.utc,
        "collected_by": "evidentia-scap-v1",
        "content": content,
        "content_hash": "0" * 64,
        "content_format": "json",
        "file_path": None,
        "file_size_bytes": None,
        "control_mappings": [],
        "sufficiency": "unknown",
        "sufficiency_rationale": None,
        "missing_elements": [],
        "validator_confidence": None,
        "validated_at": None,
        "validated_by": None,
        "expires_at": None,
        "tags": ["scap", "oval" if oval else "xccdf"],
        "metadata": metadata,
        "version": 1,
        "lineage_id": None,
        "predecessor_id": None,
    }
    ArtifactWithoutId.model_validate(artifact)
    budget.check(publication=True)
    # The inherited hash sees only counted, exact native JSON content.
    core = CoreEvidenceArtifact.model_validate({"id": "00000000-0000-5000-8000-000000000000", **artifact})
    artifact["content_hash"] = CoreEvidenceArtifact.compute_hash(core)
    budget.check(publication=True)
    frame = {"schema_version": "scap-artifact-identity-v1", "artifact_without_id": artifact}
    frame_bytes = canonical_bytes(frame, RESULT_LIMIT, budget, publication=True)
    identity = str(uuid5(_ARTIFACT_NAMESPACE, hashlib.sha256(frame_bytes).hexdigest()))
    budget.check(publication=True)
    return {"id": identity, **artifact}


def build_result(
    source: SourceBinding,
    native: NativeDocument,
    assessment: AssessmentProjection,
    request: ScapImportRequest,
    actor: AssertionActor | None,
    imported_at: datetime,
    metadata: RunMetadata,
    budget: Budget,
) -> ScapCollectionResult:
    """Construct every output field from the lifecycle's verified native components."""
    budget.check(publication=True)
    completion = _completion(source, assessment, request, actor, imported_at, budget)
    cadence = _cadence(request, assessment, completion)
    oval = source.profile != "xccdf-1.2-results"
    diagnostics = _diagnostics(assessment, completion, oval)
    artifact = _artifact(source, native, assessment, completion, cadence, budget)
    finding, manifest = _observation(source, assessment, request, imported_at, metadata, diagnostics)
    stamp = utc_text(imported_at)
    result: dict[str, object] = {
        "schema_version": "scap-collection-v1",
        "status": "imported",
        "source": source.model_dump(),
        "imported_at": stamp,
        "native_document": native.model_dump(),
        "assessment": assessment.model_dump(),
        "findings": [finding],
        "manifest": manifest,
        "completion": completion.model_dump(),
        "evidence_artifact": artifact,
        "artifact_availability": {
            "state": "available" if artifact is not None else "unavailable",
            "reasons": list(completion.qualification_reasons),
        },
        "cadence": cadence.model_dump(),
        "diagnostics": diagnostics,
    }
    measure_result(result, budget)
    accepted = ScapCollectionResult.model_validate(result)
    budget.check(publication=True)
    return accepted


def measure_result(result: dict[str, object], budget: Budget) -> int:
    """Charge all native copies plus the exact finite result remainder."""
    native_bytes = canonical_bytes(result["native_document"], NATIVE_LIMIT, budget, publication=True)
    assessment_bytes = canonical_bytes(result["assessment"], ASSESSMENT_LIMIT, budget, publication=True)
    native, assessment = len(native_bytes), len(assessment_bytes)
    remainder = {**result, "native_document": None, "assessment": None}
    artifact = result["evidence_artifact"]
    copies = 1
    if artifact is not None:
        if type(artifact) is not dict or type(artifact.get("content")) is not dict:
            raise ScapFailure()
        content = artifact["content"]
        if (
            canonical_bytes(content["native_document"], NATIVE_LIMIT, budget, publication=True) != native_bytes
            or canonical_bytes(content["assessment"], ASSESSMENT_LIMIT, budget, publication=True) != assessment_bytes
        ):
            raise ScapFailure()
        remainder["evidence_artifact"] = {
            **artifact,
            "content": {**content, "native_document": None, "assessment": None},
        }
        copies = 2
    rem = canonical_size(remainder, REMAINDER_LIMIT, budget, publication=True)
    full = rem + copies * (native - 4) + copies * (assessment - 4)
    if full > RESULT_LIMIT:
        raise ScapFailure("result_limit_exceeded")
    return full


def _observation(
    source: SourceBinding,
    assessment: AssessmentProjection,
    request: ScapImportRequest,
    imported_at: datetime,
    metadata: RunMetadata,
    diagnostics: list[dict[str, object]],
) -> tuple[dict[str, object], dict[str, object]]:
    oval = source.profile != "xccdf-1.2-results"
    stamp, finished = utc_text(imported_at), utc_text(metadata.finished_at)
    if metadata.finished_at < imported_at:
        raise ScapFailure()
    filter_applied = {
        "source_profile": source.profile,
        "source_sha256": source.sha256,
        "assessment_index": request.assessment_index,
        "selected_node_index": assessment.selection.node_index,
        "scope": "selected_assessment_native_projection",
        "time_basis": "file_import_observation",
    }
    context = {
        "collector_id": "scap",
        "collector_version": metadata.collector_version,
        "run_id": metadata.run_id,
        "collected_at": stamp,
        "credential_identity": "not-established",
        "source_system_id": "scap-source:" + source.sha256,
        "filter_applied": filter_applied,
        "pagination_context": None,
        "evidentia_version": metadata.evidentia_version,
    }
    coverage = assessment.coverage
    finding: dict[str, object] = {
        "id": assessment.finding_refs[0].finding_id,
        "title": "Imported OVAL assessment" if oval else "Imported XCCDF assessment",
        "description": (
            "One selected assessment was imported. Native outcomes remain in the full SCAP result "
            "and any evidence artifact; this summary makes no vulnerability or compliance conclusion."
        ),
        "severity": "informational",
        "status": "active",
        "compliance_status": "unknown",
        "remediation": None,
        "source_system": "scap-oval" if oval else "scap-xccdf",
        "source_finding_id": None,
        "resource_type": "scap-assessment-occurrence",
        "resource_id": None,
        "resource_region": None,
        "resource_account": None,
        "control_mappings": [],
        "collection_context": context,
        "raw_data": {
            "schema_version": "scap-assessment-summary-v1",
            "source": source.model_dump(),
            "selection": assessment.selection.model_dump(),
            "visible_unit_count": coverage.visible_unit_count,
            "selected_outcome_count": coverage.selected_outcome_count,
            "top_level_outcome_count": coverage.top_level_outcome_count,
            "countable_top_level_outcome_count": coverage.countable_top_level_outcome_count,
            "summary_only": True,
            "source_key_sha256": assessment.finding_refs[0].source_key_sha256,
        },
        "first_observed": stamp,
        "last_observed": stamp,
        "resolved_at": None,
    }
    manifest = {
        "run_id": metadata.run_id,
        "collector_id": "scap",
        "collector_version": metadata.collector_version,
        "collection_started_at": stamp,
        "collection_finished_at": finished,
        "source_system_ids": ["scap-source:" + source.sha256],
        "filters_applied": filter_applied,
        "coverage_counts": [
            {
                "resource_type": "scap-assessment-occurrence",
                "scanned": coverage.visible_unit_count,
                "matched_filter": 1,
                "collected": 1,
            }
        ],
        "total_findings": 1,
        "is_complete": True,
        "incomplete_reason": None,
        "empty_categories": [],
        "warnings": [row["message"] for row in diagnostics],
        "errors": [],
        "evidentia_version": metadata.evidentia_version,
    }
    return finding, manifest


def _checked_content_hash(content: object, budget: Budget) -> str:
    canonical = canonical_size(content, RESULT_LIMIT, budget, publication=True)
    budget.check(publication=True)
    # This verifier-owned content is already native and counted before encoding.
    # The inherited format adds only delimiter spaces to canonical JSON.
    text = ""
    encoded = b""
    try:
        text = json.dumps(content, ensure_ascii=True, sort_keys=True, allow_nan=False)
        budget.check(publication=True)
        if len(text) > canonical * 2:
            raise ScapFailure()
        encoded = text.encode("ascii")
        digest = hashlib.sha256()
        for start in range(0, len(encoded), 8192):
            budget.check(publication=True)
            digest.update(encoded[start : start + 8192])
        budget.check(publication=True)
        return digest.hexdigest()
    finally:
        text = ""
        encoded = b""


def verify_result(
    result: ScapCollectionResult,
    source: SourceBinding,
    native: NativeDocument,
    assessment: AssessmentProjection,
    request: ScapImportRequest,
    actor: AssertionActor | None,
    imported_at: datetime,
    metadata: RunMetadata,
    budget: Budget,
) -> None:
    """Check every variable output relation against retained source and run authority."""
    budget.check(publication=True)
    expected_completion = _completion(source, assessment, request, actor, imported_at, budget)
    expected_cadence = _cadence(request, assessment, expected_completion)
    oval = source.profile != "xccdf-1.2-results"
    expected_diagnostics = _diagnostics(assessment, expected_completion, oval)
    finding, manifest = _observation(source, assessment, request, imported_at, metadata, expected_diagnostics)
    if (
        result.source.model_dump() != source.model_dump()
        or result.imported_at != utc_text(imported_at)
        or result.completion.model_dump() != expected_completion.model_dump()
        or result.cadence.model_dump() != expected_cadence.model_dump()
        or [row.model_dump() for row in result.diagnostics] != expected_diagnostics
        or [row.model_dump() for row in result.findings] != [finding]
        or result.manifest.model_dump() != manifest
    ):
        raise ScapFailure()
    artifact = result.evidence_artifact
    available = expected_completion.state != "unqualified"
    if (artifact is not None) != available or result.artifact_availability.model_dump() != {
        "state": "available" if available else "unavailable",
        "reasons": list(expected_completion.qualification_reasons),
    }:
        raise ScapFailure()
    if artifact is None:
        return
    completion = {
        "basis": expected_completion.basis,
        "utc": expected_completion.utc,
        "native_ref": None if expected_completion.native_ref is None else expected_completion.native_ref.model_dump(),
        "assertion": None if expected_completion.assertion is None else expected_completion.assertion.model_dump(),
    }
    content = {
        "schema_version": "scap-evidence-v1",
        "source": source.model_dump(),
        "native_document": native.model_dump(),
        "assessment": assessment.model_dump(),
        "completion": completion,
    }
    expected_metadata: dict[str, object] = {
        "scap_contract": "scap-evidence-v1",
        "source_sha256": source.sha256,
        "source_profile": source.profile,
        "assessment_index": request.assessment_index,
        "time_basis": expected_completion.basis,
    }
    if expected_cadence.linked_slug is not None:
        expected_metadata["cadence_slug"] = expected_cadence.linked_slug
    if (
        artifact.title != ("Imported OVAL assessment" if oval else "Imported XCCDF assessment")
        or artifact.source_system != ("scap-oval" if oval else "scap-xccdf")
        or artifact.collected_at != expected_completion.utc
        or artifact.tags != ["scap", "oval" if oval else "xccdf"]
        or artifact.metadata.model_dump() != expected_metadata
        or artifact.content.model_dump() != content
        or artifact.content_hash != _checked_content_hash(content, budget)
    ):
        raise ScapFailure()
    without_id = artifact.model_dump()
    del without_id["id"]
    frame = {"schema_version": "scap-artifact-identity-v1", "artifact_without_id": without_id}
    digest = hashlib.sha256(canonical_bytes(frame, RESULT_LIMIT, budget, publication=True)).hexdigest()
    if artifact.id != str(uuid5(_ARTIFACT_NAMESPACE, digest)):
        raise ScapFailure()
    budget.check(publication=True)
