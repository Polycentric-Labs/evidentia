"""Authoritative source binding, single-use finalization and native result behavior."""

from __future__ import annotations

import hashlib
import inspect
import json
from contextlib import suppress
from datetime import UTC, datetime, timedelta, timezone
from importlib.metadata import version
from pathlib import Path

import pytest
from evidentia_collectors.scap import collector
from evidentia_collectors.scap._contracts import CompletionAssertionInput, FactoryInputs
from evidentia_collectors.scap._limits import ScapFailure

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "scap"
_PROFILES = [
    ("xccdf-1.2", "xccdf-1.2-results"),
    ("oval-5.8", "oval-5.8-core-results"),
    ("oval-5.11.2", "oval-5.11.2-core-results"),
    ("oval-5.12.3", "oval-5.12.3-core-results"),
]


def fixture(name="xccdf-1.2"):
    return (_FIXTURES / f"{name}-native.xml").read_bytes().replace(b"\r\n", b"\n")


def collect(raw=None, **kwargs):
    return collector.collect_scap_bytes(
        fixture() if raw is None else raw,
        source_profile=kwargs.pop("source_profile", "xccdf-1.2-results"),
        assessment_index=kwargs.pop("assessment_index", 0),
        **kwargs,
    )


def claim(raw, **overrides):
    values = {
        "schema_version": "scap-completion-assertion-v1",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_profile": "oval-5.8-core-results",
        "assessment_index": 0,
        "completed_at": "2024-03-01T00:00:00.000000Z",
        "reference": "Synthetic local observation",
    }
    values.update(overrides)
    return CompletionAssertionInput.model_validate(values)


@pytest.mark.parametrize("name,profile", _PROFILES)
def test_full_import_one_parse_and_exact_saved_assessment(monkeypatch, name, profile):
    calls = []
    original = collector.parse_xml

    def wrapped(raw, budget):
        calls.append((raw, budget))
        return original(raw, budget)

    monkeypatch.setattr(collector, "parse_xml", wrapped)
    before = datetime.now(UTC)
    result = collect(fixture(name), source_profile=profile)
    after = datetime.now(UTC)
    expected = json.loads((_FIXTURES / f"{name}-native.expected.json").read_text(encoding="utf-8"))
    assert len(calls) == 1
    assert result.assessment.model_dump() == expected["assessment"]
    assert result.source.sha256 == expected["source_sha256"]
    start = datetime.fromisoformat(result.imported_at)
    finish = datetime.fromisoformat(result.manifest.collection_finished_at)
    assert before <= start <= finish <= after
    assert result.manifest.collection_started_at == result.imported_at
    context = result.findings[0].collection_context
    assert context.run_id == result.manifest.run_id
    assert context.collector_version == result.manifest.collector_version == version("evidentia-collectors")
    assert context.evidentia_version == result.manifest.evidentia_version == version("evidentia-core")
    assert result.findings[0].raw_data.summary_only and result.manifest.total_findings == 1
    assert context.credential_identity == "not-established"
    assert result.manifest.warnings == [row.message for row in result.diagnostics]
    if name.startswith("oval"):
        assert result.evidence_artifact is None
        assert result.completion.qualification_reasons == ["native_completion_absent"]
    else:
        assert result.completion.state == "native_qualified"
        assert result.completion.utc == "2024-03-01T00:00:00Z"
        assert result.evidence_artifact.collected_at == result.completion.utc
        assert result.evidence_artifact.content.native_document.model_dump() == result.native_document.model_dump()


def test_import_metadata_changes_without_changing_stable_artifact_or_source_finding():
    first, second = collect(), collect()
    assert first.manifest.run_id != second.manifest.run_id
    assert first.evidence_artifact.model_dump() == second.evidence_artifact.model_dump()
    assert first.findings[0].id == second.findings[0].id
    assert first.findings[0].collection_context.run_id != second.findings[0].collection_context.run_id


@pytest.mark.parametrize(
    "replacement,reason",
    [
        (b"9999-03-01T00:00:00Z", "native_completion_future"),
        (b"2024-03-01T00:00:00", "native_completion_timezone_missing"),
        (b"2024-03-01T00:00:00.0000001Z", "native_completion_precision_unsupported"),
        (b"10000-03-01T00:00:00Z", "native_completion_range_unsupported"),
        (b"2024-03-01T00:00:60Z", "native_completion_normalization_unsupported"),
    ],
)
def test_source_valid_unqualified_completion_keeps_full_result(replacement, reason):
    raw = fixture().replace(b"2024-02-29T24:00:00-00:00", replacement)
    result = collect(raw)
    assert result.status == "imported" and result.evidence_artifact is None
    assert result.completion.native_ref is not None
    assert reason in result.completion.qualification_reasons
    assert result.artifact_availability.reasons == result.completion.qualification_reasons


def test_native_start_is_an_independent_completion_qualification():
    before = collect(fixture().replace(b'start-time="2024-02-29T23:50:00Z"', b'start-time="2025-01-01T00:00:00Z"'))
    assert before.evidence_artifact is None
    assert before.completion.qualification_reasons == ["native_completion_before_start"]
    raw = fixture().replace(b"2024-02-29T23:50:00Z", b"2024-02-29T23:50:00")
    result = collect(raw)
    assert result.completion.qualification_reasons == ["native_start_unresolved"]


def test_explicit_assertion_keeps_lexical_claim_and_distinct_actor_basis():
    raw = fixture("oval-5.8")
    assertion = claim(raw)
    result = collect(
        raw, source_profile="oval-5.8-core-results", completion_assertion=assertion, asserted_by="Synthetic operator"
    )
    assert result.completion.state == "operator_qualified"
    assert result.completion.assertion.completed_at == "2024-03-01T00:00:00.000000Z"
    assert result.completion.utc == "2024-03-01T00:00:00Z"
    assert result.completion.assertion.actor.model_dump() == {
        "basis": "caller_declared",
        "subject": "Synthetic operator",
        "provider": None,
    }
    assert (
        result.evidence_artifact.content.completion.assertion.model_dump() == result.completion.assertion.model_dump()
    )
    assert "operator_completion_asserted" in [row.code for row in result.diagnostics]
    assert "native_completion_absent" not in [row.code for row in result.diagnostics]
    second = collect(
        raw, source_profile="oval-5.8-core-results", completion_assertion=assertion, asserted_by="Different operator"
    )
    assert result.evidence_artifact.id != second.evidence_artifact.id


@pytest.mark.parametrize(
    "change,code",
    [
        ({"source_sha256": "0" * 64}, "completion_assertion_binding_mismatch"),
        ({"source_profile": "oval-5.11.2-core-results"}, "completion_assertion_binding_mismatch"),
        ({"assessment_index": 1}, "completion_assertion_binding_mismatch"),
        ({"completed_at": "9999-01-01T00:00:00Z"}, "completion_assertion_time_ineligible"),
    ],
)
def test_assertion_binding_and_future_claim_refuse(change, code):
    raw = fixture("oval-5.8")
    with pytest.raises(ScapFailure) as raised:
        collect(
            raw,
            source_profile="oval-5.8-core-results",
            completion_assertion=claim(raw, **change),
            asserted_by="Synthetic operator",
        )
    assert raised.value.code == code


@pytest.mark.parametrize(
    "kwargs,code",
    [
        ({"assessment_index": True}, "invalid_request"),
        ({"assessment_index": -1}, "invalid_request"),
        ({"source_profile": "auto"}, "unsupported_profile"),
        ({"cadence_slug": "unknown-synthetic-cadence"}, "invalid_request"),
        ({"asserted_by": "operator"}, "invalid_request"),
    ],
)
def test_invalid_options_refuse_before_parser_or_source_work(monkeypatch, kwargs, code):
    def forbidden(*args, **options):
        raise AssertionError("source work must not occur")

    monkeypatch.setattr(collector, "parse_xml", forbidden)
    with pytest.raises(ScapFailure) as raised:
        collect(**kwargs)
    assert raised.value.code == code


def test_public_signature_has_no_authority_clock_or_publish_options():
    assert set(inspect.signature(collector.collect_scap_bytes).parameters) == {
        "raw",
        "source_profile",
        "assessment_index",
        "cadence_slug",
        "completion_assertion",
        "asserted_by",
    }
    with pytest.raises(TypeError):
        collect(imported_at=datetime.now(UTC))


@pytest.mark.parametrize(
    "field", ["raw", "request", "native_document", "assessment", "imported_at", "deadline", "actor", "run_metadata"]
)
def test_each_final_factory_component_is_bound_to_retained_authority(monkeypatch, field):
    original = collector._invoke_factory

    def mutate(finalize, inputs):
        altered = dict(inputs)
        if field == "raw":
            altered[field] += b" "
        elif field == "request":
            altered[field] = {**inputs[field], "assessment_index": 1}
        elif field == "native_document":
            altered[field]["nodes"][0]["text"] = "forged"
        elif field == "assessment":
            altered[field]["coverage"]["visible_outcome_count"] += 1
        elif field == "imported_at":
            altered[field] += timedelta(seconds=1)
        elif field == "deadline":
            altered[field] += 1.0
        elif field == "actor":
            altered[field] = {"basis": "caller_declared", "subject": "forged", "provider": None}
        else:
            altered[field] = {**inputs[field], "collector_version": "forged"}
        return original(finalize, altered)

    monkeypatch.setattr(collector, "_invoke_factory", mutate)
    with pytest.raises(ScapFailure) as raised:
        collect()
    assert raised.value.code == "invalid_internal_result"


def test_matching_forged_graph_and_source_digest_do_not_prove_source(monkeypatch):
    def substitute(finalize, inputs):
        altered = inputs["raw"] + b" "
        inputs["raw"] = altered
        inputs["native_document"]["document_before"] = " "
        inputs["assessment"]["finding_refs"][0]["source_key_sha256"] = hashlib.sha256(altered).hexdigest()
        return finalize(**inputs)

    monkeypatch.setattr(collector, "_invoke_factory", substitute)
    with pytest.raises(ScapFailure):
        collect()


def test_mutated_original_request_after_capture_does_not_replace_authority():
    raw = fixture("oval-5.8")
    supplied = claim(raw).model_dump()
    actor = {"basis": "caller_declared", "subject": "initial", "provider": None}
    operation = collector._begin_import(
        source_profile="oval-5.8-core-results", assessment_index=0, completion_assertion=supplied, actor=actor
    )
    supplied["reference"] = "mutated"
    actor["subject"] = "mutated"
    result = operation.consume(raw).result
    assert result.completion.assertion.reference == "Synthetic local observation"
    assert result.completion.assertion.actor.subject == "initial"


@pytest.mark.parametrize("outcome", ["success", "failure", "cancel"])
def test_finalizer_is_consumed_at_entry_for_success_failure_and_baseexception(monkeypatch, outcome):
    original = collector._invoke_factory
    signal = KeyboardInterrupt("synthetic cancellation")
    seen = []

    def intercept(finalize, inputs):
        if outcome == "failure":
            inputs["deadline"] = float("inf")
        elif outcome == "cancel":

            def cancelled(*args, **kwargs):
                raise signal

            monkeypatch.setattr(collector, "build_result", cancelled)
        try:
            result = original(finalize, inputs)
        except BaseException as error:
            seen.append(error)
            result = None
        with pytest.raises(ScapFailure):
            original(finalize, inputs)
        if outcome == "success":
            return result
        raise seen[0]

    monkeypatch.setattr(collector, "_invoke_factory", intercept)
    if outcome == "success":
        collect()
    elif outcome == "failure":
        with pytest.raises(ScapFailure):
            collect()
    else:
        with pytest.raises(KeyboardInterrupt) as raised:
            collect()
        assert raised.value is signal


def test_import_handle_refuses_repeated_and_failed_consumption():
    for raw in (fixture(), b"<malformed"):
        operation = collector._begin_import(source_profile="xccdf-1.2-results", assessment_index=0)
        with suppress(ScapFailure):
            operation.consume(raw)
        with pytest.raises(ScapFailure):
            operation.consume(fixture())


def test_model_construction_and_extra_private_flags_are_not_factory_authority(monkeypatch):
    def constructed(finalize, inputs):
        return collector._invoke_factory(finalize, FactoryInputs.model_construct(**inputs))

    original = collector._invoke_factory

    def forged(finalize, inputs):
        return original(finalize, {**inputs, "verified": True})

    monkeypatch.setattr(collector, "_invoke_factory", forged)
    with pytest.raises(ScapFailure):
        collect()

    def model(finalize, inputs):
        return original(finalize, FactoryInputs.model_construct(**inputs))

    monkeypatch.setattr(collector, "_invoke_factory", model)
    with pytest.raises(ScapFailure):
        collect()


def test_custom_values_refuse_without_equality_encoding_or_timezone_callbacks(monkeypatch):
    events = []

    class Text(str):
        def encode(self, *args, **kwargs):
            events.append("encode")
            raise AssertionError

        def __eq__(self, other):
            events.append("equal")
            raise AssertionError

    original = collector._invoke_factory

    def altered(finalize, inputs):
        inputs["request"]["source_profile"] = Text("xccdf-1.2-results")
        return original(finalize, inputs)

    monkeypatch.setattr(collector, "_invoke_factory", altered)
    with pytest.raises(ScapFailure):
        collect()
    assert events == []

    def wrong_timezone(finalize, inputs):
        inputs["imported_at"] = datetime.now(timezone(timedelta(hours=1)))
        return original(finalize, inputs)

    monkeypatch.setattr(collector, "_invoke_factory", wrong_timezone)
    with pytest.raises(ScapFailure):
        collect()


def test_actual_metadata_failure_is_internal_dependency_failure(monkeypatch):
    def broken(name):
        raise RuntimeError("Synthetic metadata failure")

    monkeypatch.setattr(collector.metadata, "version", broken)
    with pytest.raises(ScapFailure) as raised:
        collect()
    assert raised.value.code == "internal_dependency_failure"


def test_publication_bytes_remain_immutable_after_caller_model_mutation():
    operation = collector._begin_import(source_profile="xccdf-1.2-results", assessment_index=0)
    accepted = operation.consume(fixture())
    before = accepted.output_bytes()
    accepted.result.findings.clear()
    accepted.result.native_document.nodes.clear()
    assert accepted.output_bytes() == before
    artifact = json.loads(accepted.output_bytes("artifact"))
    assert len(artifact["content"]["native_document"]["nodes"]) == 12
