"""Publication identity, complete evidence integrity and retained source changes."""

from __future__ import annotations

import hashlib
import uuid
from typing import cast

from evidentia_core.models.evidence import EvidenceArtifact

from ._contracts import (
    EventKey,
    FactComparison,
    FirstObservation,
    PublicationContent,
    ReleaseEvidenceArtifact,
    SelectedReleaseFacts,
    SourceObservationContent,
    native_model,
)
from ._json import canonical_bytes
from ._limits import ARTIFACT_BYTES, SELECTED_BYTES, SOURCE_HOST, SOURCE_PROFILE, Budget, ReleaseFailure, check_budget
from ._source import SELECTED_FIELDS, canonical_repository
from ._time import classify_publication, core_utc_text, parse_window_time, utc_text

IDENTITY_VERSION = "evidentia.release-publication.v1"
OBSERVATION_NAMESPACE = uuid.UUID("5b09e574-978a-5490-8446-a914e8a9dadf")
CHANGE_CODES = (
    "non_cadence_facts_changed",
    "publication_literal_changed",
    "node_id_changed",
    "publication_instant_changed",
    "publication_time_unqualified",
    "draft_changed_to_true",
    "prerelease_changed",
)
_CONSTANTS = {
    "release_publication": {
        "title": "GitHub release publication",
        "description": "Recorded upstream release publication. This does not show patch installation or remediation.",
        "tags": ["upstream-release", "publication"],
        "clock_kind": "source_publication",
    },
    "release_source_observation": {
        "title": "GitHub release source observation",
        "description": (
            "Recorded selected source facts for an existing upstream publication. "
            "The observation clock is retrieval time."
        ),
        "tags": ["upstream-release", "source-observation"],
        "clock_kind": "retrieval",
    },
}


def digest(value: object, maximum: int, *, budget: Budget | None = None, spaced: bool = False) -> str:
    return hashlib.sha256(canonical_bytes(value, maximum, budget=budget, spaced=spaced)).hexdigest()


def event_tuple(key: dict[str, object]) -> list[str]:
    checked = native_model(EventKey.model_validate(key))
    return [
        IDENTITY_VERSION,
        SOURCE_HOST,
        cast(str, checked["canonical_owner"]),
        cast(str, checked["canonical_repository"]),
        str(checked["release_id"]),
    ]


def event_identity(owner: object, repository: object, release_id: object) -> dict[str, object]:
    canonical_owner, canonical_repo = canonical_repository(owner, repository)
    key = {
        "identity_version": IDENTITY_VERSION,
        "source_host": SOURCE_HOST,
        "canonical_owner": canonical_owner,
        "canonical_repository": canonical_repo,
        "release_id": release_id,
    }
    key = native_model(EventKey.model_validate(key))
    raw = canonical_bytes(event_tuple(key), 1024)
    return {
        "event_key": key,
        "event_key_sha256": hashlib.sha256(raw).hexdigest(),
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, raw.decode("utf-8"))),
    }


def fact_digest(selected: object, *, budget: Budget | None = None) -> str:
    facts = native_model(SelectedReleaseFacts.model_validate(selected))
    return digest(["evidentia.release-selected-facts.v1", facts], SELECTED_BYTES + 64, budget=budget)


def observation_identity(key: dict[str, object], selected_sha: str) -> str:
    raw = canonical_bytes(
        ["evidentia.release-source-observation.v1", event_tuple(key), selected_sha],
        2048,
    )
    return str(uuid.uuid5(OBSERVATION_NAMESPACE, raw.decode("utf-8")))


def first_observation_relations(first: dict[str, object]) -> None:
    owner, repository = canonical_repository(first["requested_owner"], first["requested_repository"])
    if not owner or not repository or cast(int, first["record_index"]) > 99:
        raise ReleaseFailure("source_field")
    if first["page_number"] != first["page_ordinal"]:
        raise ReleaseFailure("source_field")
    if parse_window_time(first["retrieved_at"], normalized=True) > parse_window_time(
        first["traversal_completed_at"], normalized=True
    ):
        raise ReleaseFailure("clock_invalid")
    request = {
        "schema_version": "release-poll-request-v1",
        "source_profile": SOURCE_PROFILE,
        "owner": first["requested_owner"],
        "repository": first["requested_repository"],
        "channel": first["channel"],
        "persist": True,
    }
    if digest(request, 4096) != first["request_sha256"]:
        raise ReleaseFailure("store_digest_conflict")


def content_relations(content: dict[str, object]) -> None:
    selected = cast(dict[str, object], content["selected_facts"])
    first = cast(dict[str, object], content["first_observation"])
    first_observation_relations(first)
    identity = event_identity(first["requested_owner"], first["requested_repository"], selected["id"])
    if any(content[name] != expected for name, expected in identity.items()):
        raise ReleaseFailure("store_identity_conflict")
    if content["selected_facts_sha256"] != fact_digest(selected):
        raise ReleaseFailure("store_digest_conflict")
    source_time = classify_publication(selected["published_at"])
    if source_time != content["publication_time"]:
        raise ReleaseFailure("store_record_invalid")
    if content["record_kind"] == "release_publication":
        if (
            source_time["classification"] != "normalized"
            or selected["draft"]
            or (first["channel"] == "full_releases" and selected["prerelease"])
            or parse_window_time(source_time["normalized_utc"], normalized=True)
            > parse_window_time(first["traversal_completed_at"], normalized=True)
        ):
            raise ReleaseFailure("publication_not_eligible")
    else:
        if content["observation_id"] != observation_identity(
            cast(dict[str, object], content["event_key"]),
            cast(str, content["selected_facts_sha256"]),
        ):
            raise ReleaseFailure("store_identity_conflict")
        parent = cast(dict[str, object], content["parent_publication"])
        if parent["artifact_id"] != content["event_id"] or parent["event_key_sha256"] != content["event_key_sha256"]:
            raise ReleaseFailure("store_parent_conflict")


def artifact_relations(artifact: dict[str, object]) -> None:
    content = cast(dict[str, object], artifact["content"])
    record_kind = cast(str, content["record_kind"])
    constants = _CONSTANTS[record_kind]
    key = cast(dict[str, object], content["event_key"])
    identifier = content["event_id"] if record_kind == "release_publication" else content["observation_id"]
    if artifact["id"] != identifier or artifact["lineage_id"] != identifier:
        raise ReleaseFailure("store_identity_conflict")
    for name in ("title", "description", "tags"):
        if artifact[name] != constants[name]:
            raise ReleaseFailure("store_record_invalid")
    expected_metadata = {
        "evidentia_domain": "release-cadence",
        "schema_version": "release-evidence-metadata-v1",
        "record_kind": record_kind,
        "source_profile": SOURCE_PROFILE,
        "api_version": "2026-03-10",
        "source_host": SOURCE_HOST,
        "canonical_owner": key["canonical_owner"],
        "canonical_repository": key["canonical_repository"],
        "release_id": key["release_id"],
        "event_id": content["event_id"],
        "selected_facts_sha256": content["selected_facts_sha256"],
        "clock_kind": constants["clock_kind"],
    }
    if artifact["metadata"] != expected_metadata:
        raise ReleaseFailure("store_identity_conflict")
    if artifact["content_hash"] != digest(content, ARTIFACT_BYTES, spaced=True):
        raise ReleaseFailure("store_digest_conflict")
    time_value = (
        cast(dict[str, object], content["publication_time"])["normalized_utc"]
        if record_kind == "release_publication"
        else cast(dict[str, object], content["first_observation"])["retrieved_at"]
    )
    if artifact["collected_at"] != core_utc_text(parse_window_time(time_value, normalized=True)):
        raise ReleaseFailure("store_record_invalid")


def validate_artifact(value: object, *, budget: Budget | None = None) -> dict[str, object]:
    check_budget(budget)
    model = ReleaseEvidenceArtifact.model_validate(value)
    native = native_model(model)
    canonical_bytes(native, ARTIFACT_BYTES, budget=budget, max_depth=12, max_values=1024)
    return native


def artifact_semantic_digest(value: object, *, budget: Budget | None = None) -> str:
    native = validate_artifact(value, budget=budget)
    native["collected_at"] = utc_text(parse_window_time(native["collected_at"]))
    return digest(["evidentia.release-artifact.v1", native], ARTIFACT_BYTES + 64, budget=budget)


def _artifact(content: dict[str, object], *, budget: Budget | None) -> dict[str, object]:
    kind = cast(str, content["record_kind"])
    constants = _CONSTANTS[kind]
    key = cast(dict[str, object], content["event_key"])
    first = cast(dict[str, object], content["first_observation"])
    source_time = cast(dict[str, object], content["publication_time"])
    identifier = content["event_id"] if kind == "release_publication" else content["observation_id"]
    collected = source_time["normalized_utc"] if kind == "release_publication" else first["retrieved_at"]
    native = {
        "id": identifier,
        "title": constants["title"],
        "description": constants["description"],
        "evidence_type": "repository_metadata",
        "source_system": "github-release-cadence",
        "collected_at": core_utc_text(parse_window_time(collected, normalized=True)),
        "collected_by": SOURCE_PROFILE,
        "content": content,
        "content_hash": digest(content, ARTIFACT_BYTES, budget=budget, spaced=True),
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
        "tags": list(cast(list[str], constants["tags"])),
        "metadata": {
            "evidentia_domain": "release-cadence",
            "schema_version": "release-evidence-metadata-v1",
            "record_kind": kind,
            "source_profile": SOURCE_PROFILE,
            "api_version": "2026-03-10",
            "source_host": SOURCE_HOST,
            "canonical_owner": key["canonical_owner"],
            "canonical_repository": key["canonical_repository"],
            "release_id": key["release_id"],
            "event_id": content["event_id"],
            "selected_facts_sha256": content["selected_facts_sha256"],
            "clock_kind": constants["clock_kind"],
        },
        "version": 1,
        "lineage_id": identifier,
        "predecessor_id": None,
    }
    return validate_artifact(native, budget=budget)


def _content(selected: object, first_observation: object, *, observation: bool) -> dict[str, object]:
    facts = native_model(SelectedReleaseFacts.model_validate(selected))
    first = native_model(FirstObservation.model_validate(first_observation))
    identity = event_identity(first["requested_owner"], first["requested_repository"], facts["id"])
    return {
        "schema_version": "release-source-observation-content-v1" if observation else "release-publication-content-v1",
        "record_kind": "release_source_observation" if observation else "release_publication",
        "source_profile": SOURCE_PROFILE,
        "api_version": "2026-03-10",
        **identity,
        "selected_facts": facts,
        "selected_facts_sha256": fact_digest(facts),
        "publication_time": classify_publication(facts["published_at"]),
        "first_observation": first,
    }


def build_publication(
    selected: object,
    first_observation: object,
    *,
    budget: Budget | None = None,
) -> dict[str, object]:
    check_budget(budget)
    content = native_model(PublicationContent.model_validate(_content(selected, first_observation, observation=False)))
    return _artifact(content, budget=budget)


def build_observation(
    selected: object,
    first_observation: object,
    parent: object,
    *,
    budget: Budget | None = None,
) -> dict[str, object]:
    check_budget(budget)
    parent_native = validate_artifact(parent, budget=budget)
    parent_content = cast(dict[str, object], parent_native["content"])
    if parent_content["record_kind"] != "release_publication":
        raise ReleaseFailure("store_parent_conflict")
    content = _content(selected, first_observation, observation=True)
    if content["event_key"] != parent_content["event_key"]:
        raise ReleaseFailure("store_parent_conflict")
    if content["selected_facts"] == parent_content["selected_facts"]:
        raise ReleaseFailure("observation_not_needed")
    if content["selected_facts_sha256"] == parent_content["selected_facts_sha256"]:
        raise ReleaseFailure("store_digest_conflict")
    content["observation_id"] = observation_identity(
        cast(dict[str, object], content["event_key"]),
        cast(str, content["selected_facts_sha256"]),
    )
    content["parent_publication"] = {
        "event_key_sha256": parent_content["event_key_sha256"],
        "content_sha256": parent_native["content_hash"],
        "selected_facts_sha256": parent_content["selected_facts_sha256"],
        "artifact_id": parent_native["id"],
    }
    content = native_model(SourceObservationContent.model_validate(content))
    return _artifact(content, budget=budget)


def verify_parent(observation: object, parent: object, *, budget: Budget | None = None) -> None:
    child = validate_artifact(observation, budget=budget)
    child_content = cast(dict[str, object], child["content"])
    if child_content["record_kind"] != "release_source_observation":
        raise ReleaseFailure("store_parent_conflict")
    original = validate_artifact(parent, budget=budget)
    _parent_relations(child, original)


def _parent_relations(child: dict[str, object], original: dict[str, object]) -> None:
    """Check a pair restored only from invocation-owned validated captures."""
    child_content = cast(dict[str, object], child["content"])
    if child_content["record_kind"] != "release_source_observation":
        raise ReleaseFailure("store_parent_conflict")
    original_content = cast(dict[str, object], original["content"])
    if (
        original_content["record_kind"] != "release_publication"
        or original_content["event_key"] != child_content["event_key"]
    ):
        raise ReleaseFailure("store_parent_conflict")
    expected = {
        "event_key_sha256": original_content["event_key_sha256"],
        "content_sha256": original["content_hash"],
        "selected_facts_sha256": original_content["selected_facts_sha256"],
        "artifact_id": original["id"],
    }
    if (
        child_content["parent_publication"] != expected
        or child_content["selected_facts"] == original_content["selected_facts"]
    ):
        raise ReleaseFailure("store_parent_conflict")
    if child_content["selected_facts_sha256"] == original_content["selected_facts_sha256"]:
        raise ReleaseFailure("store_digest_conflict")


def compare_facts(parent: object, current: object) -> dict[str, object]:
    original = native_model(SelectedReleaseFacts.model_validate(parent))
    observed = native_model(SelectedReleaseFacts.model_validate(current))
    if original["id"] != observed["id"]:
        raise ReleaseFailure("store_identity_conflict")
    missing = object()
    changed = [field for field in SELECTED_FIELDS if original.get(field, missing) != observed.get(field, missing)]
    codes: set[str] = set()
    if any(
        field in changed
        for field in (
            "url",
            "html_url",
            "tag_name",
            "target_commitish",
            "name",
            "immutable",
            "created_at",
            "updated_at",
        )
    ):
        codes.add("non_cadence_facts_changed")
    if "node_id" in changed:
        codes.add("node_id_changed")
    if "published_at" in changed:
        old_time = classify_publication(original["published_at"])
        new_time = classify_publication(observed["published_at"])
        if new_time["classification"] != "normalized":
            codes.add("publication_time_unqualified")
        elif old_time["classification"] != "normalized" or new_time["normalized_utc"] != old_time["normalized_utc"]:
            codes.add("publication_instant_changed")
        else:
            codes.add("publication_literal_changed")
    if "draft" in changed and observed["draft"]:
        codes.add("draft_changed_to_true")
    if "prerelease" in changed:
        codes.add("prerelease_changed")
    ordered = [code for code in CHANGE_CODES if code in codes]
    material = any(code in codes for code in CHANGE_CODES[2:6])
    result = {
        "changed_fields": changed,
        "change_codes": ordered,
        "blocks_full_releases": material or "prerelease_changed" in codes,
        "blocks_all_published": material,
    }
    return native_model(FactComparison.model_validate(result))


def to_core_artifact(value: object, *, budget: Budget | None = None) -> EvidenceArtifact:
    expected = validate_artifact(value, budget=budget)
    # Retain immutable native authority before constructing the mutable Core object.
    expected_bytes = canonical_bytes(expected, ARTIFACT_BYTES, budget=budget, max_depth=12, max_values=1024)
    core = EvidenceArtifact.model_validate(expected)
    check_budget(budget)
    actual = EvidenceArtifact.model_dump(core, mode="json")
    if canonical_bytes(actual, ARTIFACT_BYTES, budget=budget, max_depth=12, max_values=1024) != expected_bytes:
        raise ReleaseFailure("store_record_invalid")
    # compute_hash is compatible only after exact native content validation.
    expected_hash = cast(str, expected["content_hash"])
    if EvidenceArtifact.compute_hash(core) != expected_hash:
        raise ReleaseFailure("store_digest_conflict")
    if (
        canonical_bytes(
            EvidenceArtifact.model_dump(core, mode="json"), ARTIFACT_BYTES, budget=budget, max_depth=12, max_values=1024
        )
        != expected_bytes
    ):
        raise ReleaseFailure("store_record_invalid")
    return core
