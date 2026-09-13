"""Source calendar and explicit completion eligibility through actual imports."""

from __future__ import annotations

import inspect
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from importlib import metadata
from threading import Barrier
from typing import Any, cast

import pytest
from evidentia_collectors.scap import collector
from evidentia_collectors.scap._limits import ScapFailure

from .test_source_conformance import (
    OVAL_PROFILES,
    PROFILES,
    completion_claim,
    import_source,
    source_fixture,
    xccdf_document,
)


@pytest.mark.parametrize(
    "literal,utc,reason",
    [
        ("2000-02-29T24:00:00-00:00", "2000-03-01T00:00:00Z", None),
        ("2000-03-01T00:00:00.123456000Z", "2000-03-01T00:00:00.123456Z", None),
        ("-0001-12-31T24:00:00Z", "0001-01-01T00:00:00Z", None),
        ("0001-01-01T00:01:00+00:01", "0001-01-01T00:00:00Z", None),
        ("2000-01-01T00:00:00+14:00", "1999-12-31T10:00:00Z", None),
        ("2000-01-01T00:00:00-14:00", "2000-01-01T14:00:00Z", None),
        ("2000-01-01T00:00:00", None, "native_completion_timezone_missing"),
        ("2000-01-01T00:00:00.123456001Z", None, "native_completion_precision_unsupported"),
        ("2000-01-01T00:00:60Z", None, "native_completion_normalization_unsupported"),
        ("0001-01-01T00:00:00+00:01", None, "native_completion_range_unsupported"),
        ("-0004-02-29T00:00:00Z", None, "native_completion_range_unsupported"),
        ("10000-01-01T00:00:00+14:00", "9999-12-31T10:00:00Z", "native_completion_future"),
        ("9999-12-31T24:00:00+14:00", "9999-12-31T10:00:00Z", "native_completion_future"),
    ],
)
def test_native_lexical_time_is_preserved_separately_from_artifact_qualification(
    literal: str, utc: str | None, reason: str | None
) -> None:
    result = import_source(xccdf_document(end=literal))
    observed = result.assessment.times[0]
    assert observed.role == "assessment_completion"
    assert observed.normalization.utc == utc
    root = result.native_document.model_dump()["nodes"][0]
    assert root["attributes"][1]["value"] == literal
    assert result.completion.qualification_reasons == ([] if reason is None else [reason])
    if reason is None:
        assert result.evidence_artifact is not None
        assert result.evidence_artifact.collected_at == utc
    else:
        assert result.evidence_artifact is None
        assert result.artifact_availability.reasons == [reason]
        assert result.completion.utc is None


@pytest.mark.parametrize(
    "literal",
    (
        "1900-02-29T00:00:00Z",
        "-0001-02-29T00:00:00Z",
        "0000-01-01T00:00:00Z",
        "02024-01-01T00:00:00Z",
        "+2024-01-01T00:00:00Z",
        "2000-01-01T24:00:00.0001Z",
        "2000-01-01T00:00:00+14:01",
        "2000-01-01T00:00:61Z",
        "2000-01-01T00:00:00\u00a0Z",
    ),
)
def test_source_calendar_refusal_is_not_reclassified_as_an_undated_import(literal: str) -> None:
    with pytest.raises(ScapFailure) as raised:
        import_source(xccdf_document(end=literal))
    assert cast(str, raised.value.code) == "source_contract_invalid"


@pytest.mark.parametrize(
    "start,reason",
    [("2000-03-01T00:00:01Z", "native_completion_before_start"), ("2000-03-01T00:00:00", "native_start_unresolved")],
)
def test_native_start_comparison_never_falls_back_to_ingestion(start: str, reason: str) -> None:
    result = import_source(xccdf_document(start=start, end="2000-03-01T00:00:00Z"))
    assert result.evidence_artifact is None
    assert result.completion.qualification_reasons == [reason]
    assert result.completion.native_ref is not None
    assert [row.role for row in result.assessment.times] == ["assessment_start", "assessment_completion"]


@pytest.mark.parametrize("profile", OVAL_PROFILES)
def test_generator_only_dates_never_create_native_assessment_completion(profile: str) -> None:
    raw = source_fixture(profile)
    absent = import_source(raw, profile)
    claimed = import_source(
        raw, profile, completion_assertion=completion_claim(raw, profile), asserted_by="Synthetic time reviewer"
    )
    assert all(row.role == "document_compilation" for row in absent.assessment.times)
    assert absent.evidence_artifact is None
    assert absent.completion.qualification_reasons == ["native_completion_absent"]
    assert claimed.assessment.model_dump() == absent.assessment.model_dump()
    assert claimed.native_document.model_dump() == absent.native_document.model_dump()
    assert claimed.completion.state == "operator_qualified"
    assert claimed.completion.native_ref is None
    assert claimed.completion.assertion is not None
    assert claimed.completion.assertion.completed_at == "2024-03-01T00:00:00.000000Z"
    assert claimed.completion.utc == "2024-03-01T00:00:00Z"


@pytest.mark.parametrize(
    "change,code",
    [
        ({"source_sha256": "0" * 64}, "completion_assertion_binding_mismatch"),
        ({"source_profile": OVAL_PROFILES[1]}, "completion_assertion_binding_mismatch"),
        ({"assessment_index": 1}, "completion_assertion_binding_mismatch"),
        ({"completed_at": "9999-01-01T00:00:00Z"}, "completion_assertion_time_ineligible"),
        ({"completed_at": "2000-01-01T00:00:00-00:00"}, "completion_assertion_invalid"),
        ({"completed_at": "2000-01-01T00:00:00.0000000Z"}, "completion_assertion_invalid"),
        ({"completed_at": "2000-01-01T24:00:00Z"}, "completion_assertion_invalid"),
        ({"assessment_index": True}, "completion_assertion_invalid"),
        ({"extra": "unadmitted"}, "completion_assertion_invalid"),
    ],
)
def test_claim_grammar_and_source_binding_are_separate_from_xml_time(change: dict[str, Any], code: str) -> None:
    profile = OVAL_PROFILES[0]
    raw = source_fixture(profile)
    with pytest.raises(ScapFailure) as raised:
        import_source(
            raw,
            profile,
            completion_assertion=completion_claim(raw, profile, **change),
            asserted_by="Synthetic time reviewer",
        )
    assert cast(str, raised.value.code) == code


@pytest.mark.parametrize("end", ("2000-01-01T00:00:00Z", "2000-01-01T00:00:00", "invalid-time"))
def test_no_xccdf_claim_can_override_or_repair_a_native_end(end: str) -> None:
    raw = xccdf_document(end=end)
    with pytest.raises(ScapFailure) as raised:
        import_source(
            raw, completion_assertion=completion_claim(raw, PROFILES[0]), asserted_by="Synthetic time reviewer"
        )
    assert cast(str, raised.value.code) == "completion_assertion_not_permitted"


@pytest.mark.parametrize("profile", (PROFILES[0], OVAL_PROFILES[0]))
def test_real_preclaim_anchor_governs_completion_even_after_claim_preparation(profile: str) -> None:
    before = datetime.now(UTC)
    monotonic_before = time.monotonic()
    prepared = collector._prepare_import()
    monotonic_after = time.monotonic()
    assert monotonic_before + 60.0 <= prepared.budget.deadline <= monotonic_after + 60.0
    after = datetime.now(UTC)
    time.sleep(0.003)
    later = datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if profile == PROFILES[0]:
        operation = prepared.begin(source_profile=profile, assessment_index=0)
        accepted = operation.consume(xccdf_document(end=later))
        assert before <= datetime.fromisoformat(accepted.result.imported_at) <= after
        assert accepted.original_deadline == operation.budget.deadline == prepared.budget.deadline
        assert accepted.result.completion.qualification_reasons == ["native_completion_future"]
        assert accepted.result.evidence_artifact is None
    else:
        raw = source_fixture(profile)
        claim = completion_claim(raw, profile, completed_at=later)
        operation = prepared.begin(
            source_profile=profile,
            assessment_index=0,
            completion_assertion=claim,
            actor={"basis": "caller_declared", "subject": "Synthetic anchored actor", "provider": None},
        )
        assert operation.budget.deadline == prepared.budget.deadline
        with pytest.raises(ScapFailure) as raised:
            operation.consume(raw)
        assert cast(str, raised.value.code) == "completion_assertion_time_ineligible"


def test_preparation_public_boundary_has_no_clock_or_callback_authority() -> None:
    assert list(inspect.signature(collector._prepare_import).parameters) == []
    assert set(inspect.signature(collector.collect_scap_bytes).parameters) == {
        "raw",
        "source_profile",
        "assessment_index",
        "cadence_slug",
        "completion_assertion",
        "asserted_by",
    }
    prepared = collector._prepare_import()
    for forbidden in ("budget", "deadline", "imported", "clock", "callback"):
        with pytest.raises(TypeError):
            prepared.begin(source_profile=PROFILES[0], assessment_index=0, **{forbidden: None})
    operation = prepared.begin(source_profile=PROFILES[0], assessment_index=0)
    assert operation.budget.deadline == prepared.budget.deadline


def test_cancelled_runtime_lookup_consumes_preparation_without_masking_primary(monkeypatch: pytest.MonkeyPatch) -> None:
    prepared = collector._prepare_import()
    signal = KeyboardInterrupt("synthetic cancellation")
    calls: list[str] = []

    def cancel(name: str) -> str:
        calls.append(name)
        raise signal

    monkeypatch.setattr(metadata, "version", cancel)
    with pytest.raises(KeyboardInterrupt) as raised:
        prepared.begin(source_profile=PROFILES[0], assessment_index=0)
    assert raised.value is signal
    with pytest.raises(ScapFailure) as retry:
        prepared.begin(source_profile=PROFILES[0], assessment_index=0)
    assert retry.value.code == "invalid_internal_result"
    assert calls == ["evidentia-collectors"]


def test_concurrent_begin_preserves_one_original_deadline_and_one_source_consumer() -> None:
    prepared = collector._prepare_import()
    barrier = Barrier(2)

    def begin() -> Any:
        barrier.wait(timeout=5)
        try:
            return prepared.begin(source_profile=PROFILES[0], assessment_index=0)
        except ScapFailure as error:
            assert error.code == "invalid_internal_result"
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(begin) for _ in range(2)]
        operations = [future.result(timeout=5) for future in futures]
    accepted_operations = [item for item in operations if item is not None]
    assert len(accepted_operations) == 1
    operation = accepted_operations[0]
    assert operation.budget.deadline == prepared.budget.deadline
    accepted = operation.consume(xccdf_document())
    assert accepted.original_deadline == prepared.budget.deadline
    with pytest.raises(ScapFailure):
        operation.consume(xccdf_document())
