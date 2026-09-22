"""Reachable native store and serializer limits under the original real clock."""

from __future__ import annotations

import copy
import hashlib
import json
import time
import uuid

import pytest
from evidentia_core.release_cadence._json import canonical_bytes
from evidentia_core.release_cadence._limits import RESULT_BYTES, ReleaseFailure, start_budget
from evidentia_core.release_cadence._series import release_series_bytes
from evidentia_core.release_cadence._store import discover

from ._helpers import artifact, series_request, write_artifact


def _compact(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def capacity_publication(template, identifier):
    """Apply the published tuple and hash domains with standard-library arithmetic."""
    value = copy.deepcopy(template)
    content = value["content"]
    facts = content["selected_facts"]
    facts["id"] = identifier
    facts["node_id"] = f"SYNTHETIC_CAPACITY_{identifier}"
    content["event_key"]["release_id"] = identifier
    key = ["evidentia.release-publication.v1", "api.github.com", "example", "synthetic", str(identifier)]
    spelling = _compact(key)
    identifier_text = str(uuid.uuid5(uuid.NAMESPACE_URL, spelling.decode("ascii")))
    selected_hash = hashlib.sha256(_compact(["evidentia.release-selected-facts.v1", facts])).hexdigest()
    content["event_key_sha256"] = hashlib.sha256(spelling).hexdigest()
    content["event_id"] = identifier_text
    content["selected_facts_sha256"] = selected_hash
    response_hash = hashlib.sha256(_compact([facts])).hexdigest()
    content["first_observation"]["response_raw_sha256"] = response_hash
    content["first_observation"]["response_decoded_sha256"] = response_hash
    value["metadata"].update(release_id=identifier, event_id=identifier_text, selected_facts_sha256=selected_hash)
    value["id"] = value["lineage_id"] = identifier_text
    value["content_hash"] = hashlib.sha256(json.dumps(content, sort_keys=True).encode("utf-8")).hexdigest()
    return value


@pytest.mark.parametrize("excess", [0, 1])
def test_capacity_serializer_exact_16mib_and_one_over(excess, record_property):
    # Four native strings satisfy the separate 4 MiB scalar limit.
    values = ["a" * 4_194_304 for _ in range(3)] + ["a" * (4_194_304 - 13 + excess)]
    assert sum(len(value) for value in values) + 13 == RESULT_BYTES + excess
    started = time.monotonic()
    budget = start_budget()
    if excess:
        with pytest.raises(ReleaseFailure) as found:
            canonical_bytes(values, RESULT_BYTES, budget=budget)
        assert found.value.reason == "result_limit_exceeded"
    else:
        wire = canonical_bytes(values, RESULT_BYTES, budget=budget)
        assert len(wire) == RESULT_BYTES and json.loads(wire) == values
    elapsed = time.monotonic() - started
    assert elapsed < 60
    record_property("capacity_seconds", elapsed)
    record_property("capacity_kind", "serializer_boundary_not_a_closed_result_model")


@pytest.mark.parametrize("count", [1024, 1025])
def test_capacity_complete_release_store_occurrences(tmp_path, count, record_property):
    template = artifact()
    total = 0
    for identifier in range(1, count + 1):
        total += write_artifact(tmp_path, capacity_publication(template, identifier)).stat().st_size
    started = time.monotonic()
    snapshot = discover(tmp_path, "Example", "Synthetic", start_budget())
    elapsed = time.monotonic() - started
    result = snapshot.summary()
    record_property("capacity_seconds", elapsed)
    record_property("release_records_observed", result["release_records_observed"])
    assert elapsed < 55
    if count == 1024:
        assert result["status"] == "complete" and len(snapshot.records) == 1024
        assert result["passes"] == 2 and result["release_records_observed"] == 2048
        assert result["canonical_files_read"] == 2048 and result["raw_file_bytes_observed"] == total * 2
    else:
        assert result["status"] == "limit_exceeded" and snapshot.records == ()
        assert result["release_records_observed"] == 2049


def test_capacity_series_with_maximum_discovered_publications(tmp_path, record_property):
    template = artifact()
    for identifier in range(1, 1025):
        write_artifact(tmp_path, capacity_publication(template, identifier))
    started = time.monotonic()
    wire = release_series_bytes(series_request(), evidence_store_dir=tmp_path)
    elapsed = time.monotonic() - started
    value = json.loads(wire)
    assert value["discovery"]["status"] == "complete"
    assert value["discovery"]["release_records_observed"] == 2048
    assert len(value["records"]) == len(value["events"]) == 1024
    assert len(value["gaps"]) == 1025 and value["state"] == "gapped"
    assert len(wire) <= 6_882_048 and elapsed < 60
    record_property("capacity_seconds", elapsed)
    record_property("wire_bytes", len(wire))


def _ordinary(identifier, version=1):
    from evidentia_core.models.evidence import EvidenceArtifact

    return EvidenceArtifact(
        id=identifier,
        title="Synthetic ordinary capacity record",
        evidence_type="repository_metadata",
        source_system="synthetic-capacity",
        collected_by="synthetic test",
        lineage_id=identifier,
        version=version,
    ).model_dump(mode="json")


@pytest.mark.parametrize("boundary,maximum", [("root", 4096), ("children", 16384), ("files", 8192)])
def test_capacity_native_directory_and_file_counts(tmp_path, boundary, maximum, record_property):
    identifier = "00000000-0000-4000-8000-000000000001"
    directory = tmp_path if boundary == "root" else tmp_path / identifier
    directory.mkdir(exist_ok=True)
    for index in range(maximum):
        destination = directory / (f"v{index + 1}.json" if boundary == "files" else f"ordinary-{index:05}.txt")
        destination.write_bytes(_compact(_ordinary(identifier, index + 1)) if boundary == "files" else b"")
    for excess in (0, 1):
        if excess:
            destination = directory / (f"v{maximum + 1}.json" if boundary == "files" else "ordinary-extra.txt")
            destination.write_bytes(_compact(_ordinary(identifier, maximum + 1)) if boundary == "files" else b"")
        started = time.monotonic()
        snapshot = discover(tmp_path, "Example", "Synthetic", start_budget())
        elapsed = time.monotonic() - started
        summary = snapshot.summary()
        record_property(f"capacity_seconds_{excess}", elapsed)
        record_property(f"observed_status_{excess}", summary["status"])
        key = {"root": "root_entries_observed", "children": "child_entries_observed", "files": "canonical_files_read"}[
            boundary
        ]
        assert elapsed < 55
        assert summary["status"] == ("limit_exceeded" if excess else "complete")
        assert summary[key] == maximum + 1 if excess else summary[key] == maximum * 2
        assert summary["release_records_observed"] == 0 and snapshot.records == ()
        if not excess:
            assert summary["passes"] == 2


@pytest.mark.parametrize("kind,maximum", [("release", 131072), ("ordinary", 4194304)])
def test_capacity_native_record_bytes(tmp_path, kind, maximum, record_property):
    identifier = "00000000-0000-4000-8000-000000000001"
    native = artifact() if kind == "release" else _ordinary(identifier)
    identifier = native["id"]
    directory = tmp_path / identifier
    directory.mkdir()
    raw = _compact(native)
    target = directory / "v1.json"
    for excess in (0, 1):
        target.write_bytes(raw + b" " * (maximum + excess - len(raw)))
        started = time.monotonic()
        snapshot = discover(tmp_path, "Example", "Synthetic", start_budget())
        elapsed = time.monotonic() - started
        summary = snapshot.summary()
        record_property(f"capacity_seconds_{excess}", elapsed)
        assert elapsed < 55
        assert summary["status"] == ("limit_exceeded" if excess else "complete")
        if not excess:
            assert summary["raw_file_bytes_observed"] == maximum * 2 and summary["passes"] == 2
            assert len(snapshot.records) == (1 if kind == "release" else 0)


def test_capacity_shared_store_bytes_two_passes_and_excess_probe(tmp_path, record_property):
    per_file = 4194304
    identifier = "00000000-0000-4000-8000-000000000001"
    directory = tmp_path / identifier
    directory.mkdir()
    for version in range(1, 9):
        raw = _compact(_ordinary(identifier, version))
        (directory / f"v{version}.json").write_bytes(raw + b" " * (per_file - len(raw)))
    for excess in (0, 1):
        if excess:
            (directory / "v9.json").write_bytes(_compact(_ordinary(identifier, 9)))
        started = time.monotonic()
        snapshot = discover(tmp_path, "Example", "Synthetic", start_budget())
        elapsed = time.monotonic() - started
        summary = snapshot.summary()
        record_property(f"capacity_seconds_{excess}", elapsed)
        record_property(f"raw_file_bytes_observed_{excess}", summary["raw_file_bytes_observed"])
        assert elapsed < 55
        assert summary["status"] == ("limit_exceeded" if excess else "complete")
        assert summary["raw_file_bytes_observed"] == 67108864 + excess
        if not excess:
            assert summary["canonical_files_read"] == 16 and summary["passes"] == 2


def capacity_observation(template, parent, variant):
    """Derive the separate observation UUID and parent hashes without product factories."""
    value = copy.deepcopy(template)
    content = value["content"]
    parent_content = parent["content"]
    facts = copy.deepcopy(parent_content["selected_facts"])
    facts["name"] = f"SYNTHETIC_CAPACITY_OBSERVATION_{variant}"
    content["selected_facts"] = facts
    selected_hash = hashlib.sha256(_compact(["evidentia.release-selected-facts.v1", facts])).hexdigest()
    key = ["evidentia.release-publication.v1", "api.github.com", "example", "synthetic", str(facts["id"])]
    spelling = _compact(["evidentia.release-source-observation.v1", key, selected_hash])
    identifier = str(uuid.uuid5(uuid.UUID("5b09e574-978a-5490-8446-a914e8a9dadf"), spelling.decode("ascii")))
    content["event_key"] = copy.deepcopy(parent_content["event_key"])
    content["event_key_sha256"] = parent_content["event_key_sha256"]
    content["event_id"] = parent["id"]
    content["observation_id"] = identifier
    content["selected_facts_sha256"] = selected_hash
    content["parent_publication"] = {
        "event_key_sha256": parent_content["event_key_sha256"],
        "content_sha256": parent["content_hash"],
        "selected_facts_sha256": parent_content["selected_facts_sha256"],
        "artifact_id": parent["id"],
    }
    content["publication_time"] = copy.deepcopy(parent_content["publication_time"])
    response_hash = hashlib.sha256(_compact([facts])).hexdigest()
    content["first_observation"]["response_raw_sha256"] = response_hash
    content["first_observation"]["response_decoded_sha256"] = response_hash
    value["id"] = value["lineage_id"] = identifier
    value["metadata"].update(release_id=facts["id"], event_id=parent["id"], selected_facts_sha256=selected_hash)
    value["content_hash"] = hashlib.sha256(json.dumps(content, sort_keys=True).encode("utf-8")).hexdigest()
    return value


@pytest.mark.parametrize(
    "shape,count",
    [("paired", 4), ("one_parent", 4), ("paired", 1024), ("one_parent", 1024)],
    ids=["paired-small", "one-parent-small", "paired-maximum", "one-parent-maximum"],
)
def test_capacity_series_mixed_publications_and_observations(tmp_path, shape, count, record_property):
    publication_template, observation_template = artifact(), artifact("observation-101")
    publication_count = count // 2 if shape == "paired" else 1
    expected, raw_total = {}, 0
    for identifier in range(1, publication_count + 1):
        parent = capacity_publication(publication_template, identifier)
        observations = 1 if shape == "paired" else count - 1
        values = [parent] + [
            capacity_observation(observation_template, parent, variant) for variant in range(observations)
        ]
        for value in values:
            raw = write_artifact(tmp_path, value).read_bytes()
            raw_total += len(raw)
            expected[value["id"]] = {
                "kind": value["content"]["record_kind"],
                "event_id": parent["id"],
                "content_hash": value["content_hash"],
                "fact_hash": value["content"]["selected_facts_sha256"],
                "raw_hash": hashlib.sha256(raw).hexdigest(),
            }
    assert len(expected) == count
    started = time.monotonic()
    wire = release_series_bytes(series_request(), evidence_store_dir=tmp_path)
    elapsed = time.monotonic() - started
    value = json.loads(wire)
    discovery = value["discovery"]
    assert discovery["status"] == "complete" and discovery["passes"] == 2
    assert discovery["release_records_observed"] == discovery["canonical_files_read"] == count * 2
    assert discovery["raw_file_bytes_observed"] == raw_total * 2
    assert len(value["records"]) == count and len(value["events"]) == publication_count
    assert all(event["eligibility"] == "eligible" and event["reasons"] == [] for event in value["events"])
    assert sum(event["observation_count"] for event in value["events"]) == count - publication_count
    for row in value["records"]:
        expected_row = expected[row["artifact_id"]]
        assert row["record_kind"] == expected_row["kind"]
        assert row["content_sha256"] == expected_row["content_hash"]
        assert row["selected_facts_sha256"] == expected_row["fact_hash"]
        assert row["stored_file_sha256"] == expected_row["raw_hash"]
        assert value["events"][row["event_index"]]["event_id"] == expected_row["event_id"]
    if publication_count == 1:
        assert value["state"] == "insufficient" and value["gaps"] == []
    else:
        assert value["state"] == "gapped" and len(value["gaps"]) == publication_count + 1
        assert [row["elapsed_microseconds"] for row in value["gaps"]] == (
            [86_400_000_000] + [0] * (publication_count - 1) + [172_800_000_000]
        )
    assert elapsed < 60 and len(wire) <= 6_882_048
    record_property("capacity_seconds", elapsed)
    record_property("wire_bytes", len(wire))
    record_property("shape", shape)
    record_property("publication_count", publication_count)
    record_property("observation_count", count - publication_count)
