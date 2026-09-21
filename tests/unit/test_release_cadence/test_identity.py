"""Independent pre-implementation UUID, hash and complete artifact fixtures."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from evidentia_core.release_cadence._identity import (
    artifact_semantic_digest,
    build_observation,
    build_publication,
    compare_facts,
    event_identity,
    fact_digest,
    to_core_artifact,
    validate_artifact,
)
from evidentia_core.release_cadence._limits import ReleaseFailure
from pydantic import ValidationError

FIXTURES = Path(__file__).parents[2] / "fixtures" / "release_cadence"


def expected():
    return json.loads((FIXTURES / "expected-identities.json").read_bytes())["fixtures"]


@pytest.mark.parametrize(
    "name", ["publication-101", "publication-102", "publication-103-prerelease", "observation-101"]
)
def test_all_25_fields_and_independent_hash_domains(name):
    case = expected()[name]
    artifact = case["artifact"]
    content = artifact["content"]
    selected = content["selected_facts"]
    first = content["first_observation"]
    if name.startswith("publication"):
        built = build_publication(selected, first)
    else:
        built = build_observation(selected, first, expected()["publication-101"]["artifact"])
    assert built == artifact
    assert len(built) == 25
    assert artifact_semantic_digest(built) == case["artifact_semantic_sha256"]
    assert fact_digest(selected) == content["selected_facts_sha256"]
    identity = event_identity(first["requested_owner"], first["requested_repository"], selected["id"])
    assert identity["event_id"] == content["event_id"]
    assert identity["event_key_sha256"] == content["event_key_sha256"]
    core = to_core_artifact(built)
    assert core.model_dump(mode="json") == artifact
    assert validate_artifact(artifact) == artifact


def test_fixture_bytes_reconstruct_the_original_synthetic_response():
    index = json.loads((FIXTURES / "source-index.json").read_bytes())
    for entry in index["files"]:
        raw = (FIXTURES / entry["path"]).read_bytes()
        assert len(raw) == entry["bytes"]
        assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
        if "response_sha256" in entry:
            assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
            assert len(raw) - 1 == entry["response_bytes"]
            assert hashlib.sha256(raw[:-1]).hexdigest() == entry["response_sha256"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("title", "forged"),
        ("source_system", "other"),
        ("lineage_id", None),
        ("version", True),
        ("predecessor_id", "6c57538c-991b-5d55-8e7d-90a4a05d185a"),
        ("content_hash", "0" * 64),
        ("collected_at", "2000-01-01T00:00:00.000000Z"),
    ],
)
def test_artifact_fixed_and_semantic_fields_refuse(field, value):
    artifact = expected()["publication-101"]["artifact"]
    artifact[field] = value
    with pytest.raises((ReleaseFailure, ValidationError)):
        validate_artifact(artifact)


@pytest.mark.parametrize(
    "path,value",
    [
        (("metadata", "event_id"), "15a1055c-d426-536c-93cb-a444dc0e6b5d"),
        (("content", "event_key_sha256"), "0" * 64),
        (("content", "selected_facts_sha256"), "0" * 64),
        (("content", "first_observation", "request_sha256"), "0" * 64),
        (("content", "first_observation", "record_index"), 100),
        (("content", "first_observation", "traversal_completed_at"), "1999-12-31T23:59:59.999999Z"),
    ],
)
def test_cross_copy_hash_and_qualification_refuse(path, value):
    artifact = expected()["publication-101"]["artifact"]
    target = artifact
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    with pytest.raises((ReleaseFailure, ValidationError)):
        validate_artifact(artifact)


def test_parent_binding_and_fact_changes_are_not_caller_choices():
    parent = expected()["publication-101"]["artifact"]
    observation = expected()["observation-101"]["artifact"]
    with pytest.raises((ReleaseFailure, ValidationError)):
        build_observation(parent["content"]["selected_facts"], observation["content"]["first_observation"], parent)
    forged = copy.deepcopy(parent)
    forged["content_hash"] = "0" * 64
    with pytest.raises((ReleaseFailure, ValidationError)):
        build_observation(observation["content"]["selected_facts"], observation["content"]["first_observation"], forged)


def test_literal_and_optional_changes_preserve_one_event():
    parent = expected()["publication-101"]["artifact"]["content"]["selected_facts"]
    same_instant = {**parent, "published_at": "2000-01-01T00:00:00-00:00"}
    result = compare_facts(parent, same_instant)
    assert result == {
        "changed_fields": ["published_at"],
        "change_codes": ["publication_literal_changed"],
        "blocks_full_releases": False,
        "blocks_all_published": False,
    }
    optional = {**parent, "immutable": False, "updated_at": None}
    result = compare_facts(parent, optional)
    assert result["changed_fields"] == ["immutable", "updated_at"]
    assert result["change_codes"] == ["non_cadence_facts_changed"]
    changed = {**parent, "prerelease": True, "draft": True, "published_at": None}
    result = compare_facts(parent, changed)
    assert result["change_codes"] == ["publication_time_unqualified", "draft_changed_to_true", "prerelease_changed"]
    assert result["blocks_full_releases"] and result["blocks_all_published"]


@pytest.mark.parametrize("case", ["valid", "publication_as_child", "invalid_parent", "other_parent"])
def test_public_parent_verifier_retains_full_validation_order(monkeypatch, case):
    from evidentia_core.release_cadence import _identity
    from evidentia_core.release_cadence._limits import ReleaseFailure
    from pydantic import ValidationError

    from ._helpers import artifact

    child, parent = artifact("observation-101"), artifact()
    if case == "publication_as_child":
        child = artifact()
    elif case == "invalid_parent":
        parent = {"invalid": True}
    elif case == "other_parent":
        parent = artifact("publication-102")
    original_validate, original_relation = _identity.validate_artifact, _identity._parent_relations
    calls, pairs = [], []

    def validate(value, **kwargs):
        calls.append(value)
        return original_validate(value, **kwargs)

    def relation(*args):
        pairs.append(True)
        return original_relation(*args)

    monkeypatch.setattr(_identity, "validate_artifact", validate)
    monkeypatch.setattr(_identity, "_parent_relations", relation)
    if case == "valid":
        _identity.verify_parent(child, parent)
    else:
        with pytest.raises((ReleaseFailure, ValidationError)):
            _identity.verify_parent(child, parent)
    assert len(calls) == (1 if case == "publication_as_child" else 2)
    assert calls[0] is child
    if len(calls) == 2:
        assert calls[1] is parent
    assert len(pairs) == (1 if case in {"valid", "other_parent"} else 0)


@pytest.mark.parametrize(
    "change,reason",
    [
        ("equal_facts", "store_parent_conflict"),
        ("digest_collision", "store_digest_conflict"),
        ("event_key_sha256", "store_parent_conflict"),
        ("content_sha256", "store_parent_conflict"),
        ("selected_facts_sha256", "store_parent_conflict"),
        ("artifact_id", "store_parent_conflict"),
    ],
)
def test_parent_relation_compares_native_facts_and_every_reference(change, reason):
    from evidentia_core.release_cadence import _identity

    from ._helpers import artifact

    child = validate_artifact(artifact("observation-101"))
    parent = validate_artifact(artifact())
    _identity._parent_relations(child, parent)
    content = child["content"]
    if change == "equal_facts":
        content["selected_facts"] = copy.deepcopy(parent["content"]["selected_facts"])
    elif change == "digest_collision":
        # Hypothetical collision at the pure relation seam, not a forged artifact admission.
        assert content["selected_facts"] != parent["content"]["selected_facts"]
        content["selected_facts_sha256"] = parent["content"]["selected_facts_sha256"]
    else:
        content["parent_publication"][change] = (
            "0" * 64 if change != "artifact_id" else "00000000-0000-5000-8000-000000000000"
        )
    with pytest.raises(ReleaseFailure) as caught:
        _identity._parent_relations(child, parent)
    assert caught.value.reason == reason
