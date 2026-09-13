"""Single-use SCAP import lifecycle with one authoritative source parse."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from threading import Lock
from typing import cast

import ulid
from evidentia_core.conmon.calendar import get_cadence
from pydantic import ValidationError

from ._contracts import (
    _MODELS,
    AssertionActor,
    CompletionAssertionInput,
    FactoryInputs,
    ScapCollectionResult,
    ScapImportRequest,
    SourceBinding,
    SourceProfile,
)
from ._evidence import build_result, measure_result, verify_result
from ._json import canonical_bytes, canonical_size, load_json
from ._limits import (
    ASSESSMENT_LIMIT,
    CLAIM_LIMIT,
    NATIVE_LIMIT,
    RAW_LIMIT,
    REMAINDER_LIMIT,
    RESULT_LIMIT,
    STABLE_CLAIM_LIMIT,
    Budget,
    ScapFailure,
    start_budget,
    text_value,
    utc_text,
)
from ._xml import _dependency, parse_xml
from .oval import project_oval
from .xccdf import project_xccdf

ScapSourceProfile = SourceProfile
ScapCompletionAssertion = CompletionAssertionInput
_MODEL_BY_ID = {id(model): model for model in _MODELS}
_PROFILES = ("xccdf-1.2-results", "oval-5.8-core-results", "oval-5.11.2-core-results", "oval-5.12.3-core-results")
_FACTORY_KEYS = {"raw", "request", "native_document", "assessment", "imported_at", "deadline", "actor", "run_metadata"}


@dataclass(frozen=True, slots=True)
class _Accepted:
    result: ScapCollectionResult
    wire: bytes
    budget: Budget
    original_deadline: float

    def output_bytes(self, view: str = "result") -> bytes:
        """Select immutable accepted bytes under the original publication clock."""
        if type(self.budget.deadline) is not float or self.budget.deadline != self.original_deadline:
            raise ScapFailure()
        self.budget.check(publication=True)
        if view == "result":
            return self.wire
        if view != "artifact":
            raise ScapFailure("invalid_request")
        parsed = load_json(self.wire, RESULT_LIMIT)
        if type(parsed) is not dict:
            raise ScapFailure()
        artifact = parsed["evidence_artifact"]
        if artifact is None:
            raise ScapFailure("artifact_unavailable")
        result = canonical_bytes(artifact, RESULT_LIMIT, self.budget, publication=True)
        if type(self.budget.deadline) is not float or self.budget.deadline != self.original_deadline:
            raise ScapFailure()
        self.budget.check(publication=True)
        return result


@dataclass(frozen=True, slots=True)
class _Import:
    budget: Budget
    consume: Callable[[bytes], _Accepted]


def _claim_native(value: object) -> object:
    if type(value) is CompletionAssertionInput:
        # Exact instance storage is revalidated; a model constructor proves nothing.
        return object.__getattribute__(value, "__dict__")
    return value


def _request(
    source_profile: object,
    assessment_index: object,
    cadence_slug: object,
    completion_assertion: object,
    actor: object,
    budget: Budget,
) -> tuple[bytes, bytes]:
    if type(source_profile) is not str or source_profile not in _PROFILES:
        raise ScapFailure("unsupported_profile")
    if completion_assertion is not None and source_profile == "xccdf-1.2-results":
        raise ScapFailure("completion_assertion_not_permitted")
    claim = None
    if completion_assertion is not None:
        try:
            claim_bytes = canonical_bytes(_claim_native(completion_assertion), CLAIM_LIMIT, budget)
            claim = CompletionAssertionInput.model_validate(load_json(claim_bytes, CLAIM_LIMIT)).model_dump()
        except (ScapFailure, ValidationError) as error:
            if isinstance(error, ScapFailure) and error.code == "processing_deadline_exceeded":
                raise
            raise ScapFailure("completion_assertion_invalid") from None
    try:
        if (actor is None) != (claim is None):
            raise ScapFailure()
        actor_bytes = canonical_bytes(actor, STABLE_CLAIM_LIMIT, budget)
        if actor is not None:
            actor_model = AssertionActor.model_validate(load_json(actor_bytes, STABLE_CLAIM_LIMIT))
            if (actor_model.basis == "api_authenticated" and actor_model.provider is None) or (
                actor_model.basis == "caller_declared" and actor_model.provider is not None
            ):
                raise ScapFailure()
        options = {
            "source_profile": source_profile,
            "assessment_index": assessment_index,
            "cadence_slug": cadence_slug,
            "completion_assertion": claim,
        }
        request_bytes = canonical_bytes(options, REMAINDER_LIMIT, budget)
        request = ScapImportRequest.model_validate(load_json(request_bytes, REMAINDER_LIMIT))
        if request.cadence_slug is not None and get_cadence(request.cadence_slug) is None:
            raise ScapFailure()
        budget.check()
    except (ScapFailure, ValidationError) as error:
        if isinstance(error, ScapFailure) and error.code == "processing_deadline_exceeded":
            raise
        raise ScapFailure("invalid_request") from None
    return request_bytes, actor_bytes


def _runtime(metadata_record: object, budget: Budget) -> tuple[bytes, datetime]:
    if type(metadata_record) is not dict:
        raise ScapFailure()
    record = cast(dict[str, object], metadata_record)
    if any(type(key) is not str for key in record) or record.keys() != {
        "run_id",
        "collector_version",
        "evidentia_version",
        "finished_at",
    }:
        raise ScapFailure()
    finish = record["finished_at"]
    if type(finish) is not datetime or finish.tzinfo is not UTC:
        raise ScapFailure()
    serialized = {**record, "finished_at": utc_text(finish)}
    return canonical_bytes(serialized, REMAINDER_LIMIT, budget, publication=True), finish


def _invoke_factory(finalize: Callable[..., _Accepted], inputs: dict[str, object]) -> _Accepted:
    """Pass only the eight declared private inputs to their captured derivation."""
    if type(inputs) is not dict or any(type(key) is not str for key in inputs) or inputs.keys() != _FACTORY_KEYS:
        raise ScapFailure()
    return finalize(**inputs)


@dataclass(frozen=True, slots=True)
class _PreparedImport:
    budget: Budget
    begin: Callable[..., _Import]


def _prepare_import() -> _PreparedImport:
    """Capture the original clock before an internal surface reads a claim file."""
    budget = start_budget()
    original_deadline = budget.deadline
    imported = datetime.now(UTC)
    reader_budget = Budget(original_deadline)
    preparation_lock = Lock()

    def begin(
        *,
        source_profile: object,
        assessment_index: object,
        cadence_slug: object = None,
        completion_assertion: object = None,
        actor: object = None,
    ) -> _Import:
        if not preparation_lock.acquire(blocking=False):
            raise ScapFailure()
        if (
            type(budget.deadline) is not float
            or type(reader_budget.deadline) is not float
            or budget.deadline != original_deadline
            or reader_budget.deadline != original_deadline
        ):
            raise ScapFailure()
        budget.check()
        return _bind_import(
            budget=budget,
            imported=imported,
            source_profile=source_profile,
            assessment_index=assessment_index,
            cadence_slug=cadence_slug,
            completion_assertion=completion_assertion,
            actor=actor,
        )

    return _PreparedImport(budget=reader_budget, begin=begin)


def _begin_import(
    *,
    source_profile: object,
    assessment_index: object,
    cadence_slug: object = None,
    completion_assertion: object = None,
    actor: object = None,
) -> _Import:
    """Capture real request authority before the admitted surface reads its source."""
    return _prepare_import().begin(
        source_profile=source_profile,
        assessment_index=assessment_index,
        cadence_slug=cadence_slug,
        completion_assertion=completion_assertion,
        actor=actor,
    )


def _bind_import(
    *,
    budget: Budget,
    imported: datetime,
    source_profile: object,
    assessment_index: object,
    cadence_slug: object = None,
    completion_assertion: object = None,
    actor: object = None,
) -> _Import:
    """Capture real request authority before the admitted surface reads its source."""
    original_deadline = budget.deadline
    request_bytes, actor_bytes = _request(
        source_profile, assessment_index, cadence_slug, completion_assertion, actor, budget
    )
    try:
        collector_version = text_value(metadata.version("evidentia-collectors"), 1, 64, nonblank=True, controls=True)
        core_version = text_value(metadata.version("evidentia-core"), 1, 64, nonblank=True, controls=True)
        run_id = str(ulid.ULID())
    except Exception:
        raise ScapFailure("internal_dependency_failure") from None
    _dependency()
    budget.check()
    import_lock = Lock()
    reader_budget = Budget(original_deadline)

    def restore_captured(raw: bytes, maximum: int, *, publication: bool) -> object:
        """Restore only this lifecycle's already counted immutable canonical bytes."""
        if type(raw) is not bytes or not 0 < len(raw) <= maximum:
            raise ScapFailure()
        if type(budget.deadline) is not float or budget.deadline != original_deadline:
            raise ScapFailure()
        budget.check(publication=publication)
        restored = json.loads(raw)
        budget.check(publication=publication)
        return restored

    def consume(raw_input: bytes) -> _Accepted:
        if not import_lock.acquire(blocking=False):
            raise ScapFailure()
        native_bytes = assessment_bytes = b""
        saved_raw = b""
        try:
            if (
                type(budget.deadline) is not float
                or type(reader_budget.deadline) is not float
                or budget.deadline != original_deadline
                or reader_budget.deadline != original_deadline
            ):
                raise ScapFailure()
            budget.check()
            if type(raw_input) is not bytes:
                raise ScapFailure("invalid_request")
            if len(raw_input) > RAW_LIMIT:
                raise ScapFailure("source_limit_exceeded")
            if not raw_input:
                raise ScapFailure("malformed_xml")
            saved_raw = raw_input
            source_sha256 = hashlib.sha256(saved_raw).hexdigest()
            source = SourceBinding(
                sha256=source_sha256,
                bytes=len(saved_raw),
                profile=cast(ScapSourceProfile, source_profile),
                projection_version="scap-native-document-v1",
            )
            options = ScapImportRequest.model_validate(
                restore_captured(request_bytes, REMAINDER_LIMIT, publication=False)
            )
            view = parse_xml(saved_raw, budget)
            projection = (
                project_xccdf(view, source, options.assessment_index)
                if options.source_profile == "xccdf-1.2-results"
                else project_oval(view, source, options.assessment_index)
            )
            native_bytes = canonical_bytes(view.document.model_dump(), NATIVE_LIMIT, budget)
            assessment_bytes = canonical_bytes(projection.model_dump(), ASSESSMENT_LIMIT, budget)
            candidate: dict[str, object] = {
                "raw": saved_raw,
                "request": restore_captured(request_bytes, REMAINDER_LIMIT, publication=False),
                "native_document": restore_captured(native_bytes, NATIVE_LIMIT, publication=False),
                "assessment": restore_captured(assessment_bytes, ASSESSMENT_LIMIT, publication=False),
                "imported_at": imported,
                "deadline": original_deadline,
                "actor": restore_captured(actor_bytes, STABLE_CLAIM_LIMIT, publication=False),
                "run_metadata": {
                    "run_id": run_id,
                    "collector_version": collector_version,
                    "evidentia_version": core_version,
                    "finished_at": datetime.now(UTC),
                },
            }
            runtime_bytes, finished = _runtime(candidate["run_metadata"], budget)
            if finished < imported:
                raise ScapFailure()
            finalization_lock = Lock()

            def finalize(
                *,
                raw: object,
                request: object,
                native_document: object,
                assessment: object,
                imported_at: object,
                deadline: object,
                actor: object,
                run_metadata: object,
            ) -> _Accepted:
                if not finalization_lock.acquire(blocking=False):
                    raise ScapFailure()
                if type(budget.deadline) is not float or budget.deadline != original_deadline:
                    raise ScapFailure()
                budget.check(publication=True)
                if (
                    type(raw) is not bytes
                    or raw != saved_raw
                    or type(imported_at) is not datetime
                    or imported_at.tzinfo is not UTC
                    or imported_at != imported
                    or type(deadline) is not float
                    or not math.isfinite(deadline)
                    or deadline != original_deadline
                ):
                    raise ScapFailure()
                incoming_request = canonical_bytes(request, REMAINDER_LIMIT, budget, publication=True)
                incoming_actor = canonical_bytes(actor, STABLE_CLAIM_LIMIT, budget, publication=True)
                incoming_native = canonical_bytes(native_document, NATIVE_LIMIT, budget, publication=True)
                incoming_assessment = canonical_bytes(assessment, ASSESSMENT_LIMIT, budget, publication=True)
                incoming_runtime, candidate_finished = _runtime(run_metadata, budget)
                if (
                    incoming_request != request_bytes
                    or incoming_actor != actor_bytes
                    or incoming_native != native_bytes
                    or incoming_assessment != assessment_bytes
                    or incoming_runtime != runtime_bytes
                    or candidate_finished != finished
                ):
                    raise ScapFailure()

                def authoritative_inputs() -> FactoryInputs:
                    runtime_native = restore_captured(runtime_bytes, REMAINDER_LIMIT, publication=True)
                    if type(runtime_native) is not dict:
                        raise ScapFailure()
                    return FactoryInputs.model_validate(
                        {
                            "raw": saved_raw,
                            "request": restore_captured(request_bytes, REMAINDER_LIMIT, publication=True),
                            "native_document": restore_captured(native_bytes, NATIVE_LIMIT, publication=True),
                            "assessment": restore_captured(assessment_bytes, ASSESSMENT_LIMIT, publication=True),
                            "imported_at": imported,
                            "deadline": original_deadline,
                            "actor": restore_captured(actor_bytes, STABLE_CLAIM_LIMIT, publication=True),
                            "run_metadata": {**runtime_native, "finished_at": finished},
                        }
                    )

                verified = authoritative_inputs()
                budget.check(publication=True)
                result = build_result(
                    source,
                    verified.native_document,
                    verified.assessment,
                    verified.request,
                    verified.actor,
                    verified.imported_at,
                    verified.run_metadata,
                    budget,
                )
                if type(result) is not ScapCollectionResult:
                    raise ScapFailure()
                output = _model_native(result, budget)
                # Freeze the complete candidate before validating what can be published.
                wire = canonical_bytes(output, RESULT_LIMIT, budget, publication=True)
                restored_output = restore_captured(wire, RESULT_LIMIT, publication=True)
                if type(restored_output) is not dict:
                    raise ScapFailure()
                output = cast(dict[str, object], restored_output)
                checked = ScapCollectionResult.model_validate(output)
                # Builder arguments are borrowed copies, never final verification authority.
                verified = authoritative_inputs()
                authoritative_source = SourceBinding(
                    sha256=source_sha256,
                    bytes=len(saved_raw),
                    profile=verified.request.source_profile,
                    projection_version="scap-native-document-v1",
                )
                verify_result(
                    checked,
                    authoritative_source,
                    verified.native_document,
                    verified.assessment,
                    verified.request,
                    verified.actor,
                    verified.imported_at,
                    verified.run_metadata,
                    budget,
                )
                if (
                    canonical_bytes(output["native_document"], NATIVE_LIMIT, budget, publication=True) != native_bytes
                    or canonical_bytes(output["assessment"], ASSESSMENT_LIMIT, budget, publication=True)
                    != assessment_bytes
                ):
                    raise ScapFailure()
                if type(budget.deadline) is not float or budget.deadline != original_deadline:
                    raise ScapFailure()
                measured = measure_result(output, budget)
                if measured != len(wire):
                    raise ScapFailure()
                # Rebuild the returned model from the immutable accepted serialization.
                result = ScapCollectionResult.model_validate(restore_captured(wire, RESULT_LIMIT, publication=True))
                if type(budget.deadline) is not float or budget.deadline != original_deadline:
                    raise ScapFailure()
                budget.check(publication=True)
                return _Accepted(result=result, wire=wire, budget=budget, original_deadline=original_deadline)

            return _invoke_factory(finalize, candidate)
        except ScapFailure:
            raise
        except Exception:
            raise ScapFailure() from None
        finally:
            saved_raw = native_bytes = assessment_bytes = b""

    return _Import(budget=reader_budget, consume=consume)


def _caller_actor(completion_assertion: object, asserted_by: object) -> object:
    if completion_assertion is None and asserted_by is None:
        return None
    if completion_assertion is None or asserted_by is None:
        raise ScapFailure("invalid_request")
    return {"basis": "caller_declared", "subject": asserted_by, "provider": None}


def collect_scap_bytes(
    raw: bytes,
    *,
    source_profile: ScapSourceProfile,
    assessment_index: int,
    cadence_slug: str | None = None,
    completion_assertion: ScapCompletionAssertion | None = None,
    asserted_by: str | None = None,
) -> ScapCollectionResult:
    """Import one exact byte source with explicit profile and occurrence selection."""
    operation = _begin_import(
        source_profile=source_profile,
        assessment_index=assessment_index,
        cadence_slug=cadence_slug,
        completion_assertion=completion_assertion,
        actor=_caller_actor(completion_assertion, asserted_by),
    )
    return operation.consume(raw).result


def collect_scap_file(
    path: str | Path,
    *,
    source_profile: ScapSourceProfile,
    assessment_index: int,
    cadence_slug: str | None = None,
    completion_assertion: ScapCompletionAssertion | None = None,
    asserted_by: str | None = None,
) -> ScapCollectionResult:
    """Import a stable bounded local regular file under the same source contract."""
    from ._files import read_source

    operation = _begin_import(
        source_profile=source_profile,
        assessment_index=assessment_index,
        cadence_slug=cadence_slug,
        completion_assertion=completion_assertion,
        actor=_caller_actor(completion_assertion, asserted_by),
    )
    raw = read_source(path, operation.budget)
    return operation.consume(raw).result


def _model_native(value: ScapCollectionResult, budget: Budget) -> dict[str, object]:
    """Detach known model storage without invoking custom serializers or coercions."""
    active: set[int] = set()
    total = visits = 0

    def convert(item: object, depth: int) -> object:
        nonlocal total, visits
        visits += 1
        if visits % 256 == 1:
            budget.check(publication=True)
        if depth > 128:
            raise ScapFailure()
        kind = type(item)
        if item is None or kind is bool or kind is int or kind is float or kind is str:
            total += len(cast(str, item)) + 2 if kind is str else 1
            if total > RESULT_LIMIT:
                raise ScapFailure("result_limit_exceeded")
            return item
        model = _MODEL_BY_ID.get(id(kind))
        if model is not None and kind is not model:
            raise ScapFailure()
        if kind is not dict and kind is not list and model is None:
            raise ScapFailure()
        identity = id(item)
        if identity in active:
            raise ScapFailure()
        active.add(identity)
        total += 2
        if total > RESULT_LIMIT:
            raise ScapFailure("result_limit_exceeded")
        try:
            if model is not None:
                mapping = object.__getattribute__(item, "__dict__")
                if (
                    type(mapping) is not dict
                    or any(type(key) is not str for key in mapping)
                    or mapping.keys() != model.model_fields.keys()
                ):
                    raise ScapFailure()
            elif kind is dict:
                mapping = cast(dict[str, object], item)
            else:
                return [convert(child, depth + 1) for child in cast(list[object], item)]
            result: dict[str, object] = {}
            for key, child in mapping.items():
                if type(key) is not str:
                    raise ScapFailure()
                total += len(key) + 3
                if total > RESULT_LIMIT:
                    raise ScapFailure("result_limit_exceeded")
                result[key] = convert(child, depth + 1)
            return result
        finally:
            active.remove(identity)

    native = convert(value, 0)
    if type(native) is not dict:
        raise ScapFailure()
    # Exact escaped size and scalar validity precede Pydantic reconstruction.
    canonical_size(native, RESULT_LIMIT, budget, publication=True)
    return cast(dict[str, object], native)
