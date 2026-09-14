"""Source-derived artifact fields and identities independent of factory output."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import pytest
from evidentia_collectors.scap import collector
from evidentia_collectors.scap._contracts import ScapCollectionResult
from evidentia_collectors.scap._evidence import build_result
from evidentia_collectors.scap._limits import ScapFailure

from .test_source_conformance import (
    OVAL_PROFILES,
    PROFILES,
    SLUG,
    completion_claim,
    expected_fixture,
    import_source,
    source_fixture,
)


def expected_artifact(
    profile: str,
    *,
    claim: dict[str, Any] | None = None,
    actor: dict[str, Any] | None = None,
    linked_slug: str | None = None,
) -> dict[str, Any]:
    """Construct the closed artifact from the handwritten source facts and field table."""
    expected = expected_fixture(profile)
    raw = source_fixture(profile)
    oval = profile != PROFILES[0]
    basis = "operator_asserted" if claim is not None else "native_reported"
    stable_assertion = (
        None
        if claim is None
        else {**claim, "normalized_utc": "2024-03-01T00:00:00Z", "basis": "operator_asserted", "actor": actor}
    )
    content = {
        "schema_version": "scap-evidence-v1",
        "source": {
            "sha256": expected["source_sha256"],
            "bytes": len(raw),
            "profile": profile,
            "projection_version": "scap-native-document-v1",
        },
        "native_document": copy.deepcopy(expected["native_document"]),
        "assessment": copy.deepcopy(expected["assessment"]),
        "completion": {
            "basis": basis,
            "utc": "2024-03-01T00:00:00Z",
            "native_ref": None if oval else {"node_index": 0, "slot": "attribute_value", "attribute_index": 2},
            "assertion": stable_assertion,
        },
    }
    metadata: dict[str, Any] = {
        "scap_contract": "scap-evidence-v1",
        "source_sha256": expected["source_sha256"],
        "source_profile": profile,
        "assessment_index": 0,
        "time_basis": basis,
    }
    if linked_slug is not None:
        metadata["cadence_slug"] = linked_slug
    artifact = {
        "title": "Imported OVAL assessment" if oval else "Imported XCCDF assessment",
        "description": "Native source observations with disclosed completion provenance; no authenticity, completeness or compliance conclusion.",
        "evidence_type": "test_result",
        "source_system": "scap-oval" if oval else "scap-xccdf",
        "collected_at": "2024-03-01T00:00:00Z",
        "collected_by": "evidentia-scap-v1",
        "content": content,
        "content_hash": hashlib.sha256(
            json.dumps(content, ensure_ascii=True, sort_keys=True, allow_nan=False).encode("ascii")
        ).hexdigest(),
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
    frame = {"schema_version": "scap-artifact-identity-v1", "artifact_without_id": artifact}
    digest = hashlib.sha256(
        json.dumps(frame, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    ).hexdigest()
    namespace = uuid5(NAMESPACE_URL, "https://evidentiagrc.com/scap/evidence/v1")
    return {"id": str(uuid5(namespace, digest)), **artifact}


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("requested_slug", (None, SLUG))
def test_every_artifact_field_matches_independent_source_and_identity(profile: str, requested_slug: str | None) -> None:
    raw = source_fixture(profile)
    claim = None if profile == PROFILES[0] else completion_claim(raw, profile)
    actor = (
        None
        if claim is None
        else {"basis": "caller_declared", "subject": "Synthetic independent operator", "provider": None}
    )
    eligible = profile != OVAL_PROFILES[2]
    expected = expected_artifact(profile, claim=claim, actor=actor, linked_slug=requested_slug if eligible else None)
    result = import_source(
        raw,
        profile,
        cadence_slug=requested_slug,
        completion_assertion=claim,
        asserted_by=None if actor is None else actor["subject"],
    )
    assert result.evidence_artifact is not None
    assert result.evidence_artifact.model_dump() == expected
    assert len(expected) == 25
    assert expected["content"]["native_document"] == result.native_document.model_dump()
    assert expected["content"]["assessment"] == result.assessment.model_dump()
    assert result.cadence.linked_slug == (requested_slug if eligible else None)


@pytest.mark.parametrize(
    "profile,case_index", [(PROFILES[0], 0), (PROFILES[0], 1), (OVAL_PROFILES[0], 0), (OVAL_PROFILES[0], 1)]
)
def test_previously_handwritten_identity_examples_are_still_exact(profile: str, case_index: int) -> None:
    case = expected_fixture(profile)["artifact_cases"][case_index]
    expected = expected_artifact(
        profile,
        claim=case["request"]["completion_assertion"],
        actor=case["actor"],
        linked_slug=case["request"]["cadence_slug"],
    )
    assert expected == case["evidence_artifact"]
    # API authentication itself is tested at the actual route boundary.
    operation = collector._begin_import(**case["request"], actor=case["actor"])
    accepted = operation.consume(source_fixture(profile))
    assert accepted.result.evidence_artifact is not None
    assert accepted.result.evidence_artifact.model_dump() == expected
    assert accepted.result.findings[0].id == case["finding_identity"]["finding_id"]
    assert expected["id"] == case["identity"]["artifact_id"]


@pytest.mark.parametrize("profile", OVAL_PROFILES)
def test_operational_metadata_changes_do_not_enter_stable_artifact(profile: str) -> None:
    raw = source_fixture(profile)
    options: dict[str, Any] = {
        "completion_assertion": completion_claim(raw, profile),
        "asserted_by": "Synthetic stable operator",
    }
    first, second = import_source(raw, profile, **options), import_source(raw, profile, **options)
    assert first.manifest.run_id != second.manifest.run_id
    assert first.evidence_artifact is not None and second.evidence_artifact is not None
    assert first.evidence_artifact.model_dump() == second.evidence_artifact.model_dump()
    assert first.findings[0].id == second.findings[0].id
    assert first.findings[0].collection_context.run_id != second.findings[0].collection_context.run_id
    assert set(first.evidence_artifact.content.model_dump()) == {
        "schema_version",
        "source",
        "native_document",
        "assessment",
        "completion",
    }


@pytest.mark.parametrize("change", ("actor", "reference", "raw", "cadence"))
def test_disclosed_changed_claim_domains_do_not_reuse_artifact_identity(change: str) -> None:
    profile = OVAL_PROFILES[0]
    raw = source_fixture(profile)
    claim = completion_claim(raw, profile)
    first = import_source(raw, profile, completion_assertion=claim, asserted_by="Synthetic first operator")
    if change == "raw":
        raw = raw.replace(b"SyntheticOS", b"SyntheticOS2")
        claim = completion_claim(raw, profile)
    if change == "reference":
        claim["reference"] = "Synthetic revised claim"
    second = import_source(
        raw,
        profile,
        completion_assertion=claim,
        asserted_by="Synthetic second operator" if change == "actor" else "Synthetic first operator",
        cadence_slug=SLUG if change == "cadence" else None,
    )
    assert first.evidence_artifact is not None and second.evidence_artifact is not None
    assert first.evidence_artifact.id != second.evidence_artifact.id
    assert (first.findings[0].id != second.findings[0].id) == (change == "raw")
    assert first.evidence_artifact.version == second.evidence_artifact.version == 1
    assert first.evidence_artifact.lineage_id is second.evidence_artifact.lineage_id is None


@pytest.mark.parametrize("profile", OVAL_PROFILES)
@pytest.mark.parametrize("field", ("native", "assessment", "completion", "actor", "finding"))
def test_shape_valid_forged_copies_cannot_replace_captured_source_authority(
    monkeypatch: pytest.MonkeyPatch, profile: str, field: str
) -> None:
    original = build_result

    def altered(*args: Any, **kwargs: Any) -> ScapCollectionResult:
        data = original(*args, **kwargs).model_dump()
        if field == "native":
            for native in (data["native_document"], data["evidence_artifact"]["content"]["native_document"]):
                native["nodes"][0]["tail"] = " "
        elif field == "assessment":
            for assessment in (data["assessment"], data["evidence_artifact"]["content"]["assessment"]):
                assessment["outcomes"][0]["native_result"] = "error"
        elif field == "completion":
            data["completion"]["utc"] = "2024-03-02T00:00:00Z"
            data["evidence_artifact"]["collected_at"] = "2024-03-02T00:00:00Z"
            data["evidence_artifact"]["content"]["completion"]["utc"] = "2024-03-02T00:00:00Z"
        elif field == "actor":
            data["completion"]["assertion"]["actor"]["subject"] = "Synthetic substituted actor"
            data["evidence_artifact"]["content"]["completion"]["assertion"]["actor"]["subject"] = (
                "Synthetic substituted actor"
            )
        else:
            data["findings"][0]["raw_data"]["selected_outcome_count"] = 5
        return ScapCollectionResult.model_validate(data)

    monkeypatch.setattr(collector, "build_result", altered)
    raw = source_fixture(profile)
    with pytest.raises(ScapFailure) as raised:
        import_source(
            raw, profile, completion_assertion=completion_claim(raw, profile), asserted_by="Synthetic actual actor"
        )
    assert raised.value.code == "invalid_internal_result"
