"""Independent final-output relation, hash-domain and original-clock regressions."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

import pytest
from evidentia_collectors.scap import collector
from evidentia_collectors.scap._contracts import ScapCollectionResult
from evidentia_collectors.scap._limits import Budget, ScapFailure
from evidentia_core.models.evidence import EvidenceArtifact as CoreEvidenceArtifact

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "scap"
_RAW = (_FIXTURES / "xccdf-1.2-native.xml").read_bytes().replace(b"\r\n", b"\n")

_MUTATIONS = [
    ("top_source_hash", ("source", "sha256"), "0" * 64),
    ("top_source_length", ("source", "bytes"), len(_RAW) + 1),
    ("summary_finding_id", ("findings", 0, "id"), "00000000-0000-5000-8000-000000000000"),
    ("summary_selected_count", ("findings", 0, "raw_data", "selected_outcome_count"), 99),
    ("summary_source_hash", ("findings", 0, "raw_data", "source", "sha256"), "0" * 64),
    ("finding_run_id", ("findings", 0, "collection_context", "run_id"), "00000000000000000000000000"),
    ("manifest_installed_version", ("manifest", "collector_version"), "unrelated-version"),
    ("manifest_start_anchor", ("manifest", "collection_started_at"), "2020-01-01T00:00:00Z"),
    ("manifest_source_identity", ("manifest", "source_system_ids", 0), "scap-source:" + "0" * 64),
    ("manifest_warning_mirror", ("manifest", "warnings"), []),
    ("diagnostic_applicability", ("diagnostics",), []),
    ("artifact_content_hash", ("evidence_artifact", "content_hash"), "0" * 64),
    ("artifact_id", ("evidence_artifact", "id"), "00000000-0000-5000-8000-000000000000"),
    ("artifact_metadata_binding", ("evidence_artifact", "metadata", "source_sha256"), "0" * 64),
    ("artifact_completion_date", ("evidence_artifact", "collected_at"), "2020-01-01T00:00:00Z"),
    ("completion_native_date", ("completion", "utc"), "2020-01-01T00:00:00Z"),
    ("qualified_artifact_removed", ("evidence_artifact",), None),
    ("available_state_conflict", ("artifact_availability", "state"), "unavailable"),
    ("unrequested_cadence_link", ("cadence", "linked_slug"), "synthetic-unrequested"),
    ("wrong_profile_title", ("findings", 0, "title"), "Imported OVAL assessment"),
    ("retained_native_control", ("native_document", "text"), "changed"),
    ("retained_assessment_control", ("assessment", "selection", "assessment_index"), 1),
]


@pytest.mark.parametrize("name,locator,replacement", _MUTATIONS, ids=[row[0] for row in _MUTATIONS])
def test_shape_valid_output_mutation_must_refuse_against_authority(monkeypatch, name, locator, replacement):
    original = collector.build_result

    def changed(*args, **kwargs):
        value = original(*args, **kwargs).model_dump()
        parent = value
        for key in locator[:-1]:
            parent = parent[key]
        parent[locator[-1]] = replacement
        return ScapCollectionResult.model_validate(value)

    monkeypatch.setattr(collector, "build_result", changed)
    with pytest.raises(ScapFailure) as raised:
        collector.collect_scap_bytes(_RAW, source_profile="xccdf-1.2-results", assessment_index=0)
    assert raised.value.code == "invalid_internal_result"


def test_existing_hash_called_once_and_both_identity_domains_match(monkeypatch):
    original = CoreEvidenceArtifact.compute_hash
    calls = []

    def counted(self):
        calls.append(self.content)
        return original(self)

    monkeypatch.setattr(CoreEvidenceArtifact, "compute_hash", counted)
    result = collector.collect_scap_bytes(_RAW, source_profile="xccdf-1.2-results", assessment_index=0)
    artifact = result.evidence_artifact.model_dump()
    assert len(calls) == 1
    content = json.dumps(artifact["content"], ensure_ascii=True, sort_keys=True, allow_nan=False).encode("ascii")
    assert artifact["content_hash"] == hashlib.sha256(content).hexdigest()
    frame = {
        "schema_version": "scap-artifact-identity-v1",
        "artifact_without_id": {key: value for key, value in artifact.items() if key != "id"},
    }
    digest = hashlib.sha256(
        json.dumps(frame, ensure_ascii=True, sort_keys=True, allow_nan=False, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    namespace = uuid5(NAMESPACE_URL, "https://evidentiagrc.com/scap/evidence/v1")
    assert artifact["id"] == str(uuid5(namespace, digest))
    compact_content = json.dumps(artifact["content"], sort_keys=True, separators=(",", ":")).encode("ascii")
    assert hashlib.sha256(compact_content).hexdigest() != artifact["content_hash"]
    assert result.source.sha256 == hashlib.sha256(_RAW).hexdigest()


@pytest.mark.parametrize("with_claim", [False, True])
def test_real_expired_budget_retains_deadline_failure_during_option_validation(with_claim):
    claim = {
        "schema_version": "scap-completion-assertion-v1",
        "source_sha256": "0" * 64,
        "source_profile": "oval-5.8-core-results",
        "assessment_index": 0,
        "completed_at": "2024-01-01T00:00:00Z",
        "reference": "Synthetic deadline control",
    }
    actor = {"basis": "caller_declared", "subject": "Synthetic operator", "provider": None}
    with pytest.raises(ScapFailure) as raised:
        collector._request(
            "oval-5.8-core-results",
            0,
            None,
            claim if with_claim else None,
            actor if with_claim else None,
            Budget(time.monotonic() - 1.0),
        )
    assert raised.value.code == "processing_deadline_exceeded"


def test_changed_adapter_deadline_cannot_replace_the_original_capture():
    operation = collector._begin_import(source_profile="xccdf-1.2-results", assessment_index=0)
    original = operation.budget.deadline
    object.__setattr__(operation.budget, "deadline", original + 60.0)
    with pytest.raises(ScapFailure) as raised:
        operation.consume(_RAW)
    assert raised.value.code == "invalid_internal_result"


def test_changed_output_budget_cannot_extend_publication():
    operation = collector._begin_import(source_profile="xccdf-1.2-results", assessment_index=0)
    accepted = operation.consume(_RAW)
    object.__setattr__(accepted.budget, "deadline", accepted.budget.deadline + 60.0)
    with pytest.raises(ScapFailure):
        accepted.output_bytes()


@pytest.mark.parametrize(
    "argument,field,value",
    [
        (0, "sha256", "0" * 64),
        (0, "bytes", len(_RAW) + 1),
        (0, "profile", "oval-5.8-core-results"),
        (3, "assessment_index", 1),
        (3, "cadence_slug", "nist-800-53-rev5-ca7"),
        (6, "run_id", "00000000000000000000000000"),
        (6, "collector_version", "altered-version"),
        (6, "evidentia_version", "altered-core-version"),
    ],
)
def test_builder_borrowed_objects_cannot_change_verification_authority(monkeypatch, argument, field, value):
    original = collector.build_result

    def altered(*args, **kwargs):
        object.__setattr__(args[argument], field, value)
        return original(*args, **kwargs)

    monkeypatch.setattr(collector, "build_result", altered)
    with pytest.raises(ScapFailure) as raised:
        collector.collect_scap_bytes(_RAW, source_profile="xccdf-1.2-results", assessment_index=0)
    assert raised.value.code == "invalid_internal_result"


def test_artifact_output_deadline_drift_during_serialization_is_refused(monkeypatch):
    operation = collector._begin_import(source_profile="xccdf-1.2-results", assessment_index=0)
    accepted = operation.consume(_RAW)
    original = collector.canonical_bytes

    def extend(value, maximum, budget, *args, **kwargs):
        object.__setattr__(budget, "deadline", accepted.original_deadline + 60.0)
        return original(value, maximum, budget, *args, **kwargs)

    monkeypatch.setattr(collector, "canonical_bytes", extend)
    with pytest.raises(ScapFailure) as raised:
        accepted.output_bytes("artifact")
    assert raised.value.code == "invalid_internal_result"


def test_adapter_clock_equality_callback_is_never_invoked():
    operation = collector._begin_import(source_profile="xccdf-1.2-results", assessment_index=0)
    calls = []

    class Clock:
        def __eq__(self, other):
            calls.append(other)
            return True

    object.__setattr__(operation.budget, "deadline", Clock())
    with pytest.raises(ScapFailure) as raised:
        operation.consume(_RAW)
    assert raised.value.code == "invalid_internal_result"
    assert calls == []


def test_explicit_isolated_persistence_keeps_stable_version_one_and_refuses_duplicate(tmp_path, monkeypatch):
    from evidentia_core import evidence_store

    directory = tmp_path / "isolated-evidence"
    monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(directory))
    monkeypatch.delenv(evidence_store.EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR, raising=False)
    monkeypatch.delenv(evidence_store.EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR, raising=False)
    first = collector.collect_scap_bytes(_RAW, source_profile="xccdf-1.2-results", assessment_index=0)
    second = collector.collect_scap_bytes(_RAW, source_profile="xccdf-1.2-results", assessment_index=0)
    assert not directory.exists()
    assert first.evidence_artifact.model_dump() == second.evidence_artifact.model_dump()
    artifact = CoreEvidenceArtifact.model_validate(first.evidence_artifact.model_dump())
    assert artifact.version == 1 and artifact.lineage_id is None and artifact.predecessor_id is None
    target = evidence_store.save_evidence(artifact, directory)
    before = target.read_bytes()
    with pytest.raises(evidence_store.EvidenceWORMViolation) as collision:
        evidence_store.save_evidence(
            CoreEvidenceArtifact.model_validate(second.evidence_artifact.model_dump()), directory
        )
    assert collision.value.attempted_version == 1 and collision.value.next_version == 2
    assert target.read_bytes() == before
    stored = CoreEvidenceArtifact.model_validate_json(before)
    assert stored.model_dump() == artifact.model_dump()
    assert list(directory.rglob("v*.json")) == [target]


@pytest.mark.parametrize("stage", ["before_wire", "before_measure", "after_measure"])
@pytest.mark.parametrize("copies", ["top", "artifact", "both"])
def test_same_length_late_mutation_never_changes_accepted_wire(monkeypatch, stage, copies):
    expected = json.loads((_FIXTURES / "xccdf-1.2-native.expected.json").read_text(encoding="utf-8"))
    changed = []

    def mutate(value):
        targets = []
        if copies in {"top", "both"}:
            targets.append(value["native_document"])
        if copies in {"artifact", "both"}:
            targets.append(value["evidence_artifact"]["content"]["native_document"])
        for target in targets:
            name = target["nodes"][0]["name"]["local_name"]
            target["nodes"][0]["name"]["local_name"] = "Z" + name[1:]
        changed.append(True)

    if stage == "before_wire":
        encode = collector.canonical_bytes

        def before_wire(value, *args, **kwargs):
            if type(value) is dict and {"native_document", "assessment", "evidence_artifact"} <= value.keys():
                mutate(value)
            return encode(value, *args, **kwargs)

        monkeypatch.setattr(collector, "canonical_bytes", before_wire)
    else:
        measure = collector.measure_result

        def around_measure(value, *args, **kwargs):
            if stage == "before_measure":
                mutate(value)
            measured = measure(value, *args, **kwargs)
            if stage == "after_measure":
                mutate(value)
            return measured

        monkeypatch.setattr(collector, "measure_result", around_measure)
    try:
        accepted = collector._begin_import(source_profile="xccdf-1.2-results", assessment_index=0).consume(_RAW)
    except ScapFailure as failure:
        assert failure.code == "invalid_internal_result"
    else:
        wire = json.loads(accepted.output_bytes())
        assert wire["native_document"] == expected["native_document"]
        assert wire["evidence_artifact"]["content"]["native_document"] == expected["native_document"]
        assert accepted.result.model_dump() == wire
    assert changed


@pytest.mark.parametrize("stage", ["hash", "after_encoding"])
def test_verifier_owned_encoded_buffers_release_on_cancellation_and_deadline(monkeypatch, stage):
    from evidentia_collectors.scap import _evidence, _limits

    class Cancelled(BaseException):
        pass

    primary = Cancelled()
    now = [1.0]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: now[0])
    original_encode = _evidence.json.dumps

    def encode(*args, **kwargs):
        result = original_encode(*args, **kwargs)
        if stage == "after_encoding":
            now[0] = 60.0
        return result

    class Digest:
        def update(self, chunk):
            raise primary

    monkeypatch.setattr(_evidence.json, "dumps", encode)
    monkeypatch.setattr(_evidence.hashlib, "sha256", Digest)
    content = {"synthetic": ["retained authority"]}
    with pytest.raises(Cancelled if stage == "hash" else ScapFailure) as raised:
        _evidence._checked_content_hash(content, Budget(60.0))
    if stage == "hash":
        assert raised.value is primary
    else:
        assert raised.value.code == "processing_deadline_exceeded"
    trace = raised.value.__traceback__
    observed = False
    while trace is not None:
        frame = trace.tb_frame
        if frame.f_code.co_name == "_checked_content_hash":
            observed = True
            assert frame.f_locals["text"] == ""
            assert frame.f_locals["encoded"] == b""
        trace = trace.tb_next
    assert observed and content == {"synthetic": ["retained authority"]}
