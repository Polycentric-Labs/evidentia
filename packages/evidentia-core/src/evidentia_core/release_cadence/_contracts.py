"""Closed executable release source, evidence, poll and series field tables."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import timedelta
from functools import partial
from typing import Annotated, Any, ClassVar, Literal, Self, cast

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ModelWrapValidatorHandler,
    SerializationInfo,
    SerializerFunctionWrapHandler,
    ValidationInfo,
    field_validator,
    model_serializer,
    model_validator,
)

from ._json import _string_size, canonical_bytes, detach, load_json
from ._limits import ERRORS, RESULT_BYTES, ReleaseFailure, integer, text_value
from ._source import SELECTED_FIELDS, canonical_repository, selected_facts
from ._time import classify_publication, core_utc_text, parse_window_time


def _exact(kind: type, value: object) -> object:
    if type(value) is not kind:
        raise ReleaseFailure()
    return value


def _literal(expected: object, value: object) -> object:
    if type(expected) is not type(value) or expected != value:
        raise ReleaseFailure()
    return value


def _text(maximum: int, minimum: int, pattern: str | None, value: object) -> str:
    text = text_value(value, maximum, minimum=minimum)
    if pattern is not None and re.fullmatch(pattern, text) is None:
        raise ReleaseFailure()
    return text


def _schema_constraints(values: dict[str, object], schema: dict[str, object]) -> None:
    """Expose existing field constraints without changing validator execution."""
    schema.pop("ge", None)
    schema.pop("le", None)
    schema.update(values)


def _number(minimum: int, maximum: int, value: object) -> int:
    return integer(value, minimum, maximum)


def _sequence(minimum: int, maximum: int, value: object) -> list[object]:
    if type(value) is not list or not minimum <= len(cast(list[object], value)) <= maximum:
        raise ReleaseFailure()
    return cast(list[object], value)


def _utc(form: str, value: object) -> str:
    text = text_value(value, 27)
    instant = parse_window_time(text, normalized=form == "normalized")
    if form == "core" and core_utc_text(instant) != text:
        raise ReleaseFailure()
    return text


_MODEL_TYPES: dict[int, type[ClosedModel]] = {}


def native_model(value: object) -> dict[str, object]:
    """Copy bounded exact model storage without serializers or foreign callbacks."""
    root_kind = _MODEL_TYPES.get(id(type(value)))
    maximum = root_kind.canonical_limit if root_kind is type(value) else RESULT_BYTES
    max_values = root_kind.input_values if root_kind is type(value) else RESULT_BYTES
    max_depth = root_kind.input_depth if root_kind is type(value) else 64
    seen: set[int] = set()
    owned: list[dict[str, object] | list[object]] = []
    cache: dict[str, int] = {}
    total = 0
    count = 0

    def add(size: int) -> None:
        nonlocal total
        total += size
        if total > maximum:
            raise ReleaseFailure("json_scalar")

    def charge(depth: int) -> None:
        nonlocal count
        count += 1
        if count > max_values:
            raise ReleaseFailure("json_count")
        if depth > max_depth:
            raise ReleaseFailure("json_depth")

    def string_size(text: str, *, key: bool = False) -> int:
        if len(text) <= 64 and text.isascii():
            found = cache.get(text)
            if found is not None:
                return found
        size = _string_size(text, 256 if key else min(maximum, 4_194_304), None)
        if len(cache) < 512 and len(text) <= 64 and text.isascii():
            cache[text] = size
        return size

    def copy(item: object, depth: int) -> object:
        charge(depth)
        kind = type(item)
        model_kind = _MODEL_TYPES.get(id(kind))
        if model_kind is kind:
            identity = id(item)
            if identity in seen:
                raise ReleaseFailure()
            seen.add(identity)
            values = object.__getattribute__(item, "__dict__")
            fields_set = object.__getattribute__(item, "__pydantic_fields_set__")
            if type(values) is not dict or type(fields_set) is not set:
                raise ReleaseFailure()
            if any(type(key) is not str for key in values) or any(type(key) is not str for key in fields_set):
                raise ReleaseFailure()
            if values.keys() != model_kind.model_fields.keys() or not fields_set.issubset(values.keys()):
                raise ReleaseFailure()
            keys = [
                name for name in model_kind.model_fields if name not in model_kind.optional_fields or name in fields_set
            ]
            add(2 + max(0, len(keys) - 1))
            output: dict[str, object] = {}
            owned.append(output)
            for name in keys:
                charge(depth + 1)
                add(string_size(name, key=True) + 1)
                output[name] = copy(values[name], depth + 1)
            return output
        if kind is list or kind is dict:
            identity = id(item)
            if identity in seen:
                raise ReleaseFailure()
            seen.add(identity)
            size = len(cast(list[object] | dict[str, object], item))
            if size > max_values - count:
                raise ReleaseFailure("json_count")
            add(2 + max(0, size - 1))
            if kind is list:
                sequence: list[object] = []
                owned.append(sequence)
                for child in cast(list[object], item):
                    sequence.append(copy(child, depth + 1))
                return sequence
            mapping = cast(dict[str, object], item)
            if any(type(key) is not str for key in mapping):
                raise ReleaseFailure()
            copied: dict[str, object] = {}
            owned.append(copied)
            for key, child in mapping.items():
                charge(depth + 1)
                add(string_size(key, key=True) + 1)
                copied[key] = copy(child, depth + 1)
            return copied
        if kind is str:
            add(string_size(cast(str, item)))
        elif kind is bool or item is None:
            add(4 if item is None or item is True else 5)
        elif kind is int:
            if cast(int, item).bit_length() > 426:
                raise ReleaseFailure("json_scalar")
            spelling = str(item)
            if len(spelling) > 128:
                raise ReleaseFailure("json_scalar")
            add(len(spelling))
        elif kind is float:
            if not math.isfinite(cast(float, item)):
                raise ReleaseFailure("json_scalar")
            add(len(json.dumps(item, allow_nan=False)))
        else:
            raise ReleaseFailure()
        return item

    try:
        result = copy(value, 1)
        if type(result) is not dict:
            raise ReleaseFailure()
        return cast(dict[str, object], result)
    except BaseException:
        for container in owned:
            container.clear()
        raise
    finally:
        seen.clear()
        cache.clear()
        owned.clear()


class ClosedModel(BaseModel):
    """Native-only immutable model shell; every published graph is recaptured."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        revalidate_instances="always",
        hide_input_in_errors=True,
    )
    canonical_limit: ClassVar[int] = RESULT_BYTES
    input_limit: ClassVar[int] = RESULT_BYTES
    input_depth: ClassVar[int] = 64
    input_values: ClassVar[int] = RESULT_BYTES
    optional_fields: ClassVar[frozenset[str]] = frozenset()

    @model_validator(mode="wrap")
    @classmethod
    def original_native_ingress(
        cls, value: object, handler: ModelWrapValidatorHandler[Self], info: ValidationInfo
    ) -> Self:
        if _MODEL_TYPES.get(id(cls)) is not cls or info.mode == "json" or type(value) is not dict:
            raise ReleaseFailure()
        return handler(value)

    @model_validator(mode="before")
    @classmethod
    def native_ingress(cls, value: object, info: ValidationInfo) -> object:
        if _MODEL_TYPES.get(id(cls)) is not cls or info.mode == "json" or type(value) is not dict:
            raise ReleaseFailure()
        mapping = cast(dict[str, object], value)
        if any(type(key) is not str for key in mapping):
            raise ReleaseFailure()
        keys = mapping.keys()
        if not keys <= cls.model_fields.keys() or not cls.model_fields.keys() - cls.optional_fields <= keys:
            raise ReleaseFailure()
        return detach(
            mapping,
            cls.canonical_limit,
            max_values=cls.input_values,
            max_depth=cls.input_depth,
        )

    @model_validator(mode="after")
    def relations(self) -> Self:
        native = native_model(self)
        _relations(type(self).__name__, native)
        canonical_bytes(native, self.canonical_limit, max_values=self.input_values, max_depth=self.input_depth)
        return self

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        extra: Literal["allow", "ignore", "forbid"] | None = None,
        context: Any = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        if type(json_data) is bytes:
            raw = json_data
        elif type(json_data) is str:
            text_value(json_data, cls.input_limit)
            raw = json_data.encode("utf-8")
        else:
            raise ReleaseFailure()
        native = load_json(raw, cls.input_limit, max_values=cls.input_values, max_depth=cls.input_depth)
        return cls.model_validate(
            native,
            strict=strict,
            extra=extra,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )


def _relations(name: str, value: dict[str, object]) -> None:
    if name in ("PollRequest", "ReleaseSeriesRequest"):
        canonical_repository(value["owner"], value["repository"])
        if name == "ReleaseSeriesRequest":
            start = parse_window_time(value["window_start"])
            end = parse_window_time(value["window_end"])
            if not start < end or end - start > timedelta(days=36_600):
                raise ReleaseFailure()
    elif name in ("PollScope", "SeriesScope", "EventKey", "ReleaseEvidenceMetadata"):
        owner, repository = canonical_repository(value["canonical_owner"], value["canonical_repository"])
        if owner != value["canonical_owner"] or repository != value["canonical_repository"]:
            raise ReleaseFailure()
    elif name in ("PublicationContent", "SourceObservationContent"):
        from ._identity import content_relations

        content_relations(value)
    elif name == "FirstObservation":
        from ._identity import first_observation_relations

        first_observation_relations(value)
    elif name == "ReleaseEvidenceArtifact":
        from ._identity import artifact_relations

        artifact_relations(value)
    elif name == "SelectedReleaseFacts":
        if selected_facts(value) != value:
            raise ReleaseFailure()
    elif name == "SourcePublicationTime":
        if classify_publication(value["source_literal"]) != value:
            raise ReleaseFailure()
    elif name == "SourceTimeView":
        if (value["classification"] == "normalized") != (value["normalized_utc"] is not None):
            raise ReleaseFailure()
    elif name == "ReleaseSeriesResult":
        from ._series import series_relations

        series_relations(value)
    elif name == "PollResult":
        _poll_relations(cast(dict[str, Any], value))
    elif name == "LocalSaveOutcome":
        _outcome_relations(cast(dict[str, Any], value))
    elif name == "ReleaseError":
        if ERRORS[cast(str, value["code"])][1] != value["message"]:
            raise ReleaseFailure()
    elif name == "StoredRecordReference":
        if value["relative_path"] != str(value["artifact_id"]) + "/v1.json":
            raise ReleaseFailure()
    elif name == "FactComparison":
        fields = cast(list[str], value["changed_fields"])
        codes = cast(list[str], value["change_codes"])
        if fields != [field for field in SELECTED_FIELDS if field in fields]:
            raise ReleaseFailure()
        if codes != [code for code in CHANGE_CODES if code in codes]:
            raise ReleaseFailure()
        material = any(code in codes for code in CHANGE_CODES[2:6])
        if value["blocks_all_published"] != material or value["blocks_full_releases"] != (
            material or "prerelease_changed" in codes
        ):
            raise ReleaseFailure()
        if bool(fields) != bool(codes):
            raise ReleaseFailure()


def publication_eligibility(
    selected: dict[str, Any], channel: str, completed_at: str | None
) -> tuple[dict[str, object], list[str], bool]:
    """Derive source eligibility without inventing a partial-traversal clock."""
    classified = classify_publication(selected["published_at"])
    reasons = []
    if selected["draft"]:
        reasons.append("draft")
    if channel == "full_releases" and selected["prerelease"]:
        reasons.append("prerelease_excluded")
    if classified["classification"] == "absent":
        reasons.append("publication_time_absent")
    elif classified["classification"] != "normalized":
        reasons.append("publication_time_unsupported")
    elif completed_at is not None and parse_window_time(classified["normalized_utc"]) > parse_window_time(completed_at):
        reasons.append("publication_time_future")
    return (
        {
            "classification": classified["classification"],
            "normalized_utc": classified["normalized_utc"],
        },
        reasons,
        completed_at is not None and not reasons,
    )


def _outcome_relations(value: dict[str, Any]) -> None:
    outcome, call, state = value["outcome"], value["save_call"], value["local_state"]
    record, reason = value["verified_record"], value["reason"]
    rules: dict[str, tuple[str, set[str], set[str | None] | None, bool | None]] = {
        "created": ("local_verified", {"returned_created"}, {None}, True),
        "already_saved": ("local_verified", {"not_called", "returned_collided"}, {None}, True),
        "existing_different_facts": ("local_verified", {"returned_collided", "raised"}, {None, "save_failed"}, True),
        "present_after_uncertain_save": ("local_verified", {"raised"}, {"save_failed"}, True),
        "not_applicable": (
            "not_attempted",
            {"not_called"},
            {"publication_not_eligible", "observation_not_needed", "known_parent_absent"},
            False,
        ),
        "not_attempted": ("not_attempted", {"not_called"}, None, False),
        "failed": ("local_absent", {"raised"}, {"save_failed"}, False),
        "indeterminate": (
            "local_indeterminate",
            {"returned_created", "returned_collided", "raised"},
            {"store_changed", "store_unavailable", "store_limit_exceeded", "deadline_exceeded", "cancelled"},
            False,
        ),
        "conflict": (
            "local_conflict",
            {"returned_created", "returned_collided", "raised"},
            {
                "save_readback_mismatch",
                "store_record_invalid",
                "store_identity_conflict",
                "store_digest_conflict",
                "store_parent_missing",
                "store_parent_conflict",
                "store_changed",
            },
            None,
        ),
    }
    expected = rules[outcome]
    if state != expected[0] or call not in expected[1]:
        raise ReleaseFailure()
    allowed_reasons = expected[2]
    if (allowed_reasons is None and reason is None) or (allowed_reasons is not None and reason not in allowed_reasons):
        raise ReleaseFailure()
    required_record = expected[3]
    if required_record is not None and (record is not None) != required_record:
        raise ReleaseFailure()
    if value["record_kind"] == "release_publication":
        if value["candidate_id"] != value["event_id"] or value["planned_action"] not in {
            "create_publication",
            "reuse_publication",
        }:
            raise ReleaseFailure()
    elif value["planned_action"] not in {"create_observation", "conditional_observation"}:
        raise ReleaseFailure()
    if value["planned_action"] == "reuse_publication" and (call != "not_called" or outcome != "already_saved"):
        raise ReleaseFailure()
    if outcome == "existing_different_facts" and (
        value["record_kind"] != "release_publication" or reason != ("save_failed" if call == "raised" else None)
    ):
        raise ReleaseFailure()
    if record is not None:
        if (
            record["record_kind"] != value["record_kind"]
            or record["artifact_id"] != value["candidate_id"]
            or record["event_id"] != value["event_id"]
        ):
            raise ReleaseFailure()
        same = record["selected_facts_sha256"] == value["candidate_selected_facts_sha256"]
        if outcome in {"created", "already_saved", "present_after_uncertain_save"} and not same:
            raise ReleaseFailure()
        if outcome == "existing_different_facts" and same:
            raise ReleaseFailure()


def _poll_relations(value: dict[str, Any]) -> None:
    from ._identity import event_identity, event_tuple, fact_digest, observation_identity

    request, scope = value["request"], value["scope"]
    owner, repository = canonical_repository(request["owner"], request["repository"])
    if (
        value["request_sha256"] != hashlib.sha256(canonical_bytes(request, 4096)).hexdigest()
        or (scope["canonical_owner"], scope["canonical_repository"]) != (owner, repository)
        or scope["channel"] != request["channel"]
    ):
        raise ReleaseFailure()
    clocks = value["clocks"]
    start, end = parse_window_time(clocks["started_at"]), parse_window_time(clocks["completed_at"])
    completion = clocks["traversal_completed_at"]
    if end < start or (completion is not None and not start <= parse_window_time(completion) <= end):
        raise ReleaseFailure()
    pages, rows, events, outcomes = value["pages"], value["rows"], value["events"], value["outcomes"]
    raw = decoded = admitted = row_count = 0
    last_receipt = start
    empty_digest = hashlib.sha256(b"[]").hexdigest()
    for index, page in enumerate(pages):
        if (page["page_index"], page["page_ordinal"], page["page_number"]) != (index, index + 1, index + 1):
            raise ReleaseFailure()
        if index and (not pages[index - 1]["admitted"] or pages[index - 1]["next_page"] != index + 1):
            raise ReleaseFailure()
        raw += page["raw_bytes_observed"]
        decoded += page["decoded_bytes_observed"]
        for prefix in ("raw", "decoded"):
            if page[f"{prefix}_body_complete"] != (page[f"{prefix}_body_sha256"] is not None):
                raise ReleaseFailure()
            if page[f"{prefix}_body_complete"] and page[f"{prefix}_bytes_observed"] > 4194304:
                raise ReleaseFailure()
        if page["decoded_body_complete"] and not page["raw_body_complete"]:
            raise ReleaseFailure()
        receipt = page["retrieved_at"]
        if receipt is not None:
            instant = parse_window_time(receipt)
            if not page["decoded_body_complete"] or not last_receipt <= instant <= end:
                raise ReleaseFailure()
            if completion is not None and instant > parse_window_time(completion):
                raise ReleaseFailure()
            last_receipt = instant
        relations = [page[field] for field in ("first_page", "previous_page", "next_page", "last_page")]
        state = page["link_state"]
        if state in {"absent", "invalid", "unavailable"} and any(relation is not None for relation in relations):
            raise ReleaseFailure()
        if state == "absent" and page["link_values_sha256"] != empty_digest:
            raise ReleaseFailure()
        if state == "unavailable" and page["link_values_sha256"] is not None:
            raise ReleaseFailure()
        if state == "valid":
            if page["link_values_sha256"] in (None, empty_digest) or all(relation is None for relation in relations):
                raise ReleaseFailure()
            first, previous, following, last = relations
            if (
                (first is not None and first != 1)
                or (previous is not None and (index == 0 or previous != index))
                or (following is not None and following != index + 2)
                or (last is not None and last < max(index + 1, following or index + 1))
                or (following is None and last is not None and last > index + 1)
            ):
                raise ReleaseFailure()
        if page["admitted"]:
            if (
                page["http_status"] != 200
                or receipt is None
                or not page["raw_body_complete"]
                or not page["decoded_body_complete"]
                or state not in {"absent", "valid"}
                or page["row_start"] != row_count
                or page["decoded_row_count"] != page["row_count"]
                or page["json_value_key_occurrences"] is None
                or page["json_depth_observed"] is None
            ):
                raise ReleaseFailure()
            for position in range(page["row_count"]):
                if row_count + position >= len(rows):
                    raise ReleaseFailure()
                metadata = rows[row_count + position]["metadata"]
                if (metadata["page_index"], metadata["record_index"]) != (index, position):
                    raise ReleaseFailure()
            row_count += page["row_count"]
            admitted += 1
        elif page["row_start"] is not None or page["row_count"] != 0 or index != len(pages) - 1:
            raise ReleaseFailure()
        if page["reason"] is not None and (index != len(pages) - 1 or page["reason"] != value["terminal_reason"]):
            raise ReleaseFailure()
        canonical_bytes(page, 12288)
    if row_count != len(rows):
        raise ReleaseFailure()
    terminal, collection = value["terminal_reason"], value["collection_state"]
    if collection == "complete":
        if (
            completion is None
            or terminal is not None
            or not pages
            or admitted != len(pages)
            or pages[-1]["next_page"] is not None
            or any(page["reason"] is not None for page in pages)
        ):
            raise ReleaseFailure()
    elif completion is not None or terminal is None or (collection == "partial") != bool(admitted):
        raise ReleaseFailure()
    if terminal == "page_limit" and (
        len(pages) != 10 or not pages[-1]["admitted"] or pages[-1]["next_page"] != 11 or pages[-1]["reason"] != terminal
    ):
        raise ReleaseFailure()
    selected_size = 0
    facts_by_id: dict[int, bytes] = {}
    members: dict[int, list[int]] = {}
    for index, row in enumerate(rows):
        selected, metadata = row["selected"], row["metadata"]
        encoded = canonical_bytes(selected, 16384)
        selected_size += len(encoded)
        identifier = selected["id"]
        if identifier in facts_by_id and facts_by_id[identifier] != encoded:
            raise ReleaseFailure()
        facts_by_id[identifier] = encoded
        members.setdefault(identifier, []).append(index)
        source_time, reasons, eligible = publication_eligibility(selected, request["channel"], completion)
        if (
            metadata["row_index"] != index
            or metadata["selected_facts_sha256"] != fact_digest(selected)
            or metadata["source_time"] != source_time
            or metadata["eligibility_reasons"] != reasons
            or metadata["initial_publication_eligible"] != eligible
        ):
            raise ReleaseFailure()
        canonical_bytes({"metadata": metadata}, 2048)
    ordered = sorted(
        members,
        key=lambda identifier: tuple(
            event_tuple(cast(dict[str, object], event_identity(owner, repository, identifier)["event_key"]))
        ),
    )
    if len(events) != len(ordered):
        raise ReleaseFailure()
    used_slots: set[int] = set()
    for index, (event, release_id) in enumerate(zip(events, ordered, strict=True)):
        identity = event_identity(owner, repository, release_id)
        positions = members[release_id]
        if (
            event["event_index"] != index
            or event["release_id"] != release_id
            or event["event_id"] != identity["event_id"]
            or event["representative_row_index"] != positions[0]
            or event["occurrence_count"] != len(positions)
            or any(rows[position]["metadata"]["event_index"] != index for position in positions)
        ):
            raise ReleaseFailure()
        parent_slot = event["publication_outcome_index"]
        observation_slot = event["observation_outcome_index"]
        for slot, kind in ((parent_slot, "release_publication"), (observation_slot, "release_source_observation")):
            if slot is None:
                continue
            if slot >= len(outcomes) or slot in used_slots:
                raise ReleaseFailure()
            used_slots.add(slot)
            outcome = outcomes[slot]
            if outcome["event_id"] != event["event_id"] or outcome["record_kind"] != kind:
                raise ReleaseFailure()
            representative = rows[positions[0]]
            source_sha = representative["metadata"]["selected_facts_sha256"]
            if (
                outcome["planned_action"] != "reuse_publication"
                and outcome["candidate_selected_facts_sha256"] != source_sha
            ):
                raise ReleaseFailure()
            if kind == "release_source_observation":
                expected_id = observation_identity(cast(dict[str, object], identity["event_key"]), source_sha)
                if outcome["candidate_id"] != expected_id:
                    raise ReleaseFailure()
        state = event["stored_state"]
        if state in {"not_observed", "unavailable"}:
            if (
                event["known_observation_count"] is not None
                or event["current_vs_parent"] is not None
                or event["stored_union_change_codes"]
                or event["blocks_full_releases"] is not None
                or event["blocks_all_published"] is not None
            ):
                raise ReleaseFailure()
        elif state == "absent" and (
            event["known_observation_count"] != 0
            or event["current_vs_parent"] is not None
            or event["stored_union_change_codes"]
            or event["blocks_full_releases"] is not False
            or event["blocks_all_published"] is not False
        ):
            raise ReleaseFailure()
        if event["current_vs_parent"] is not None:
            if parent_slot is None or outcomes[parent_slot]["verified_record"] is None:
                raise ReleaseFailure()
            parent = outcomes[parent_slot]["verified_record"]
            comparison = event["current_vs_parent"]
            source_sha = rows[positions[0]]["metadata"]["selected_facts_sha256"]
            if (source_sha == parent["selected_facts_sha256"]) != (not comparison["changed_fields"]):
                raise ReleaseFailure()
            union = event["stored_union_change_codes"]
            if union != [code for code in CHANGE_CODES if code in union] or not set(comparison["change_codes"]) <= set(
                union
            ):
                raise ReleaseFailure()
            material = any(code in union for code in CHANGE_CODES[2:6])
            if event["blocks_all_published"] != material or event["blocks_full_releases"] != (
                material or "prerelease_changed" in union
            ):
                raise ReleaseFailure()
        elif state == "verified":
            raise ReleaseFailure()
        canonical_bytes(event, 2048)
    if used_slots != set(range(len(outcomes))):
        raise ReleaseFailure()
    counters, discovery, persistence = value["counters"], value["discovery"], value["persistence"]
    expected_counters = {
        "attempts": len(pages),
        "pages_admitted": admitted,
        "rows_admitted": len(rows),
        "unique_source_events": len(events),
        "raw_entity_bytes_observed": raw,
        "decoded_entity_bytes_observed": decoded,
        "selected_ccompact_bytes_admitted": selected_size,
        "total_store_raw_bytes_observed": discovery["raw_file_bytes_observed"]
        + counters["targeted_raw_bytes_observed"],
    }
    if any(counters[name] != expected for name, expected in expected_counters.items()):
        raise ReleaseFailure()
    if selected_size > 8388608:
        raise ReleaseFailure()
    called = [index for index, outcome in enumerate(outcomes) if outcome["save_call"] != "not_called"]
    counts = {name: sum(outcome["outcome"] == name for outcome in outcomes) for name in persistence["outcome_counts"]}
    if (
        persistence["requested"] != request["persist"]
        or persistence["planned_slots"] != len(outcomes)
        or persistence["attempted_calls"] != len(called)
        or persistence["last_attempted_slot"] != (called[-1] if called else None)
        or persistence["outcome_counts"] != counts
        or counters["targeted_record_reads"] > 2 * len(called)
    ):
        raise ReleaseFailure()
    state, stop = persistence["state"], persistence["stop_reason"]
    if not request["persist"]:
        if (
            state != "not_requested"
            or stop is not None
            or outcomes
            or discovery["status"] != "not_requested"
            or counters["targeted_record_reads"]
            or counters["targeted_raw_bytes_observed"]
            or counters["total_store_raw_bytes_observed"]
            or any(event["stored_state"] != "not_observed" for event in events)
        ):
            raise ReleaseFailure()
    elif state == "not_requested":
        raise ReleaseFailure()
    elif state == "not_started":
        if (
            called
            or stop is None
            or any(
                outcome["outcome"] not in {"already_saved", "not_attempted", "not_applicable"} for outcome in outcomes
            )
        ):
            raise ReleaseFailure()
    elif state == "complete":
        if (
            stop is not None
            or collection != "complete"
            or discovery["status"] != "complete"
            or any(
                outcome["outcome"] not in {"created", "already_saved", "existing_different_facts", "not_applicable"}
                or outcome["save_call"] == "raised"
                for outcome in outcomes
            )
        ):
            raise ReleaseFailure()
    elif state == "partial":
        if not called or stop is None or any(outcome["outcome"] == "indeterminate" for outcome in outcomes):
            raise ReleaseFailure()
    elif not called or stop is None or not any(outcome["outcome"] == "indeterminate" for outcome in outcomes):
        raise ReleaseFailure()
    if discovery["status"] in {"not_requested", "not_started"} and (
        any(
            discovery[name] != 0
            for name in (
                "passes",
                "root_entries_observed",
                "child_entries_observed",
                "canonical_files_read",
                "raw_file_bytes_observed",
                "release_record_reads_observed",
            )
        )
        or any(
            discovery[name] is not None for name in ("inventory_sha256", "selected_scope_records", "conflicting_events")
        )
    ):
        raise ReleaseFailure()
    if discovery["status"] == "complete" and (
        discovery["passes"] != 2
        or discovery["inventory_sha256"] is None
        or discovery["selected_scope_records"] is None
        or discovery["conflicting_events"] != 0
    ):
        raise ReleaseFailure()
    if discovery["inventory_sha256"] is not None and discovery["passes"] != 2:
        raise ReleaseFailure()
    if collection != "complete" and (called or discovery["status"] not in {"not_requested", "not_started"}):
        raise ReleaseFailure()
    reasons = list(dict.fromkeys(reason for reason in (terminal, stop) if reason is not None))
    if value["reasons"] != reasons:
        raise ReleaseFailure()


ExactBoolean = Annotated[bool, BeforeValidator(partial(_exact, bool))]

ReleaseId = Annotated[
    int,
    BeforeValidator(partial(_number, 1, 9007199254740991)),
    Field(
        ge=1,
        le=9007199254740991,
        json_schema_extra=partial(_schema_constraints, {"minimum": 1, "maximum": 9007199254740991}),
    ),
]

Sha256 = Annotated[
    str,
    BeforeValidator(partial(_text, 64, 64, "^[0-9a-f]{64}$")),
    Field(
        min_length=64,
        max_length=64,
        pattern="^[0-9a-f]{64}$",
        json_schema_extra=partial(_schema_constraints, {"minLength": 64, "maxLength": 64, "pattern": "^[0-9a-f]{64}$"}),
    ),
]

ApplicationUuid = Annotated[
    str,
    BeforeValidator(partial(_text, 36, 36, "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")),
    Field(
        min_length=36,
        max_length=36,
        pattern="^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        json_schema_extra=partial(
            _schema_constraints,
            {
                "minLength": 36,
                "maxLength": 36,
                "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            },
        ),
    ),
]

PollUuid = Annotated[
    str,
    BeforeValidator(partial(_text, 36, 36, "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")),
    Field(
        min_length=36,
        max_length=36,
        pattern="^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        json_schema_extra=partial(
            _schema_constraints,
            {
                "minLength": 36,
                "maxLength": 36,
                "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            },
        ),
    ),
]

NativeText16K = Annotated[
    str,
    BeforeValidator(partial(_text, 16384, 0, None)),
    Field(
        min_length=0,
        max_length=16384,
        json_schema_extra=partial(_schema_constraints, {"minLength": 0, "maxLength": 16384}),
    ),
]

SourceTimestamp128 = Annotated[
    str,
    BeforeValidator(partial(_text, 128, 0, None)),
    Field(
        min_length=0, max_length=128, json_schema_extra=partial(_schema_constraints, {"minLength": 0, "maxLength": 128})
    ),
]

RequestedRepositoryToken256 = Annotated[
    str,
    BeforeValidator(partial(_text, 256, 1, "^[A-Za-z0-9._-]{1,256}$")),
    Field(
        min_length=1,
        max_length=256,
        pattern="^[A-Za-z0-9._-]{1,256}$",
        json_schema_extra=partial(
            _schema_constraints, {"minLength": 1, "maxLength": 256, "pattern": "^[A-Za-z0-9._-]{1,256}$"}
        ),
    ),
]

CanonicalRepositoryToken256 = Annotated[
    str,
    BeforeValidator(partial(_text, 256, 1, "^[a-z0-9._-]{1,256}$")),
    Field(
        min_length=1,
        max_length=256,
        pattern="^[a-z0-9._-]{1,256}$",
        json_schema_extra=partial(
            _schema_constraints, {"minLength": 1, "maxLength": 256, "pattern": "^[a-z0-9._-]{1,256}$"}
        ),
    ),
]

NormalizedUtc = Annotated[
    Annotated[
        str,
        BeforeValidator(partial(_text, 27, 27, None)),
        Field(
            min_length=27,
            max_length=27,
            json_schema_extra=partial(_schema_constraints, {"minLength": 27, "maxLength": 27}),
        ),
    ],
    BeforeValidator(partial(_utc, "normalized")),
]

CoreUtcWire = Annotated[
    Annotated[
        str,
        BeforeValidator(partial(_text, 27, 20, None)),
        Field(
            min_length=20,
            max_length=27,
            json_schema_extra=partial(_schema_constraints, {"minLength": 20, "maxLength": 27}),
        ),
    ],
    BeforeValidator(partial(_utc, "core")),
]

ReleaseChannel = Annotated[Literal["full_releases", "all_published"], BeforeValidator(partial(_exact, str))]

ReleaseRecordKind = Annotated[
    Literal["release_publication", "release_source_observation"], BeforeValidator(partial(_exact, str))
]

PublicationTimeClassification = Annotated[
    Literal[
        "absent",
        "unsupported_syntax",
        "unsupported_year",
        "invalid_calendar",
        "unsupported_leap_second",
        "unsupported_precision",
        "utc_out_of_range",
        "normalized",
    ],
    BeforeValidator(partial(_exact, str)),
]

SelectedFieldName = Annotated[
    Literal[
        "id",
        "node_id",
        "url",
        "html_url",
        "tag_name",
        "target_commitish",
        "name",
        "draft",
        "prerelease",
        "immutable",
        "created_at",
        "published_at",
        "updated_at",
    ],
    BeforeValidator(partial(_exact, str)),
]

ChangeCode = Annotated[
    Literal[
        "non_cadence_facts_changed",
        "publication_literal_changed",
        "node_id_changed",
        "publication_instant_changed",
        "publication_time_unqualified",
        "draft_changed_to_true",
        "prerelease_changed",
    ],
    BeforeValidator(partial(_exact, str)),
]

ReadbackReason = Annotated[
    Literal[
        "store_record_invalid",
        "store_identity_conflict",
        "store_digest_conflict",
        "store_parent_missing",
        "store_parent_conflict",
        "store_changed",
        "store_unavailable",
        "store_limit_exceeded",
        "deadline_exceeded",
        "cancelled",
    ],
    BeforeValidator(partial(_exact, str)),
]

SaveReason = Annotated[
    Literal[
        "publication_not_eligible",
        "observation_not_needed",
        "known_parent_absent",
        "save_failed",
        "save_readback_mismatch",
        "store_record_invalid",
        "store_identity_conflict",
        "store_digest_conflict",
        "store_parent_missing",
        "store_parent_conflict",
        "store_changed",
        "store_unavailable",
        "store_limit_exceeded",
        "deadline_exceeded",
        "cancelled",
    ],
    BeforeValidator(partial(_exact, str)),
]

LocalDisposition = Annotated[
    Literal[
        "created",
        "already_saved",
        "existing_different_facts",
        "present_after_uncertain_save",
        "not_applicable",
        "not_attempted",
        "failed",
        "indeterminate",
        "conflict",
    ],
    BeforeValidator(partial(_exact, str)),
]

LocalState = Annotated[
    Literal["local_verified", "local_absent", "local_conflict", "local_indeterminate", "not_attempted"],
    BeforeValidator(partial(_exact, str)),
]

WindowUtc = Annotated[
    Annotated[
        str,
        BeforeValidator(partial(_text, 27, 20, None)),
        Field(
            min_length=20,
            max_length=27,
            json_schema_extra=partial(_schema_constraints, {"minLength": 20, "maxLength": 27}),
        ),
    ],
    BeforeValidator(partial(_utc, "window")),
]

FixedReason = Annotated[
    Literal[
        "offline_refused",
        "destination_refused",
        "dns_failure",
        "tls_failure",
        "connection_failure",
        "timeout",
        "cleanup_failure",
        "dependency_unavailable",
        "dependency_broken",
        "invalid_response",
        "unsupported_media",
        "unsupported_encoding",
        "unsupported_link",
        "page_limit",
        "row_limit",
        "raw_limit",
        "decoded_limit",
        "json_syntax",
        "json_depth",
        "json_count",
        "json_scalar",
        "source_field",
        "source_conflict",
        "selected_limit",
        "result_limit",
        "clock_invalid",
        "deadline_exceeded",
        "cancelled",
        "redirect_refused",
        "upstream_unauthorized",
        "upstream_forbidden",
        "upstream_not_found",
        "upstream_rate_limited",
        "upstream_server_error",
        "upstream_http_error",
        "store_record_invalid",
        "store_identity_conflict",
        "store_digest_conflict",
        "store_parent_missing",
        "store_parent_conflict",
        "store_changed",
        "store_unavailable",
        "store_limit_exceeded",
        "publication_not_eligible",
        "observation_not_needed",
        "known_parent_absent",
        "save_failed",
        "save_readback_mismatch",
    ],
    BeforeValidator(partial(_exact, str)),
]

CHANGE_CODES = (
    "non_cadence_facts_changed",
    "publication_literal_changed",
    "node_id_changed",
    "publication_instant_changed",
    "publication_time_unqualified",
    "draft_changed_to_true",
    "prerelease_changed",
)


class SelectedReleaseFacts(ClosedModel):
    canonical_limit = 16384
    optional_fields = frozenset(["immutable", "updated_at"])
    id: ReleaseId
    node_id: NativeText16K
    url: NativeText16K
    html_url: NativeText16K
    tag_name: NativeText16K
    target_commitish: NativeText16K
    name: NativeText16K | None
    draft: ExactBoolean
    prerelease: ExactBoolean
    # None represents an omitted internal slot, never an admitted source null.
    immutable: ExactBoolean | None = Field(default=None)
    created_at: SourceTimestamp128
    published_at: SourceTimestamp128 | None
    updated_at: SourceTimestamp128 | None = Field(default=None)

    @field_validator("immutable", mode="before")
    @classmethod
    def present_immutable_boolean(cls, value: object) -> bool:
        return cast(bool, _exact(bool, value))

    @model_serializer(mode="wrap")
    def preserve_absence(self, handler: SerializerFunctionWrapHandler, info: SerializationInfo) -> dict[str, Any]:
        output = handler(self)
        for field in self.optional_fields:
            if field not in self.model_fields_set:
                output.pop(field, None)
        return cast(dict[str, Any], output)

    @classmethod
    def __get_pydantic_json_schema__(cls, core_schema: Any, handler: Any) -> dict[str, Any]:
        source_schema = dict(core_schema)
        current = source_schema
        while True:
            current.pop("serialization", None)
            nested = current.get("schema")
            if type(nested) is not dict:
                break
            current["schema"] = dict(nested)
            current = current["schema"]
        schema = handler(source_schema)
        resolved = handler.resolve_ref_schema(schema)
        for field in cls.optional_fields:
            resolved.get("properties", {}).get(field, {}).pop("default", None)
        immutable_schema = resolved.get("properties", {}).get("immutable", {})
        immutable_schema.pop("anyOf", None)
        immutable_schema["type"] = "boolean"
        return cast(dict[str, Any], schema)


class EventKey(ClosedModel):
    canonical_limit = 1024
    identity_version: Annotated[
        Literal["evidentia.release-publication.v1"],
        BeforeValidator(partial(_literal, "evidentia.release-publication.v1")),
    ]
    source_host: Annotated[Literal["api.github.com"], BeforeValidator(partial(_literal, "api.github.com"))]
    canonical_owner: CanonicalRepositoryToken256
    canonical_repository: CanonicalRepositoryToken256
    release_id: ReleaseId


class SourcePublicationTime(ClosedModel):
    canonical_limit = 1024
    source_literal: SourceTimestamp128 | None
    classification: PublicationTimeClassification
    normalized_utc: NormalizedUtc | None


class FirstObservation(ClosedModel):
    canonical_limit = 4096
    poll_id: PollUuid
    request_sha256: Sha256
    requested_owner: RequestedRepositoryToken256
    requested_repository: RequestedRepositoryToken256
    channel: ReleaseChannel
    page_ordinal: Annotated[
        int,
        BeforeValidator(partial(_number, 1, 10)),
        Field(ge=1, le=10, json_schema_extra=partial(_schema_constraints, {"minimum": 1, "maximum": 10})),
    ]
    page_number: Annotated[
        int,
        BeforeValidator(partial(_number, 1, 9007199254740991)),
        Field(
            ge=1,
            le=9007199254740991,
            json_schema_extra=partial(_schema_constraints, {"minimum": 1, "maximum": 9007199254740991}),
        ),
    ]
    record_index: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 999)),
        Field(ge=0, le=999, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 999})),
    ]
    retrieved_at: NormalizedUtc
    traversal_completed_at: NormalizedUtc
    response_raw_sha256: Sha256
    response_decoded_sha256: Sha256


class ParentPublication(ClosedModel):
    canonical_limit = 512
    event_key_sha256: Sha256
    content_sha256: Sha256
    selected_facts_sha256: Sha256
    artifact_id: ApplicationUuid


class PublicationContent(ClosedModel):
    canonical_limit = 32768
    schema_version: Annotated[
        Literal["release-publication-content-v1"], BeforeValidator(partial(_literal, "release-publication-content-v1"))
    ]
    record_kind: Annotated[Literal["release_publication"], BeforeValidator(partial(_literal, "release_publication"))]
    source_profile: Annotated[
        Literal["github-public-releases-2026-03-10"],
        BeforeValidator(partial(_literal, "github-public-releases-2026-03-10")),
    ]
    api_version: Annotated[Literal["2026-03-10"], BeforeValidator(partial(_literal, "2026-03-10"))]
    event_key: EventKey
    event_key_sha256: Sha256
    event_id: ApplicationUuid
    selected_facts: SelectedReleaseFacts
    selected_facts_sha256: Sha256
    publication_time: SourcePublicationTime
    first_observation: FirstObservation


class SourceObservationContent(ClosedModel):
    canonical_limit = 32768
    schema_version: Annotated[
        Literal["release-source-observation-content-v1"],
        BeforeValidator(partial(_literal, "release-source-observation-content-v1")),
    ]
    record_kind: Annotated[
        Literal["release_source_observation"], BeforeValidator(partial(_literal, "release_source_observation"))
    ]
    source_profile: Annotated[
        Literal["github-public-releases-2026-03-10"],
        BeforeValidator(partial(_literal, "github-public-releases-2026-03-10")),
    ]
    api_version: Annotated[Literal["2026-03-10"], BeforeValidator(partial(_literal, "2026-03-10"))]
    event_key: EventKey
    event_key_sha256: Sha256
    event_id: ApplicationUuid
    observation_id: ApplicationUuid
    parent_publication: ParentPublication
    selected_facts: SelectedReleaseFacts
    selected_facts_sha256: Sha256
    publication_time: SourcePublicationTime
    first_observation: FirstObservation


class ReleaseEvidenceMetadata(ClosedModel):
    canonical_limit = 2048
    evidentia_domain: Annotated[Literal["release-cadence"], BeforeValidator(partial(_literal, "release-cadence"))]
    schema_version: Annotated[
        Literal["release-evidence-metadata-v1"], BeforeValidator(partial(_literal, "release-evidence-metadata-v1"))
    ]
    record_kind: ReleaseRecordKind
    source_profile: Annotated[
        Literal["github-public-releases-2026-03-10"],
        BeforeValidator(partial(_literal, "github-public-releases-2026-03-10")),
    ]
    api_version: Annotated[Literal["2026-03-10"], BeforeValidator(partial(_literal, "2026-03-10"))]
    source_host: Annotated[Literal["api.github.com"], BeforeValidator(partial(_literal, "api.github.com"))]
    canonical_owner: CanonicalRepositoryToken256
    canonical_repository: CanonicalRepositoryToken256
    release_id: ReleaseId
    event_id: ApplicationUuid
    selected_facts_sha256: Sha256
    clock_kind: Annotated[Literal["source_publication", "retrieval"], BeforeValidator(partial(_exact, str))]


class StoredRecordReference(ClosedModel):
    canonical_limit = 1536
    record_kind: ReleaseRecordKind
    artifact_id: ApplicationUuid
    event_id: ApplicationUuid
    version: Annotated[Literal[1], BeforeValidator(partial(_literal, 1))]
    relative_path: Annotated[
        str,
        BeforeValidator(partial(_text, 44, 44, "^[0-9a-f-]{36}/v1\\.json$")),
        Field(
            min_length=44,
            max_length=44,
            pattern="^[0-9a-f-]{36}/v1\\.json$",
            json_schema_extra=partial(
                _schema_constraints, {"minLength": 44, "maxLength": 44, "pattern": "^[0-9a-f-]{36}/v1\\.json$"}
            ),
        ),
    ]
    content_sha256: Sha256
    selected_facts_sha256: Sha256
    artifact_semantic_sha256: Sha256
    stored_file_sha256: Sha256
    stored_file_bytes: Annotated[
        int,
        BeforeValidator(partial(_number, 1, 131072)),
        Field(ge=1, le=131072, json_schema_extra=partial(_schema_constraints, {"minimum": 1, "maximum": 131072})),
    ]
    collected_at: NormalizedUtc
    first_observation_poll_id: PollUuid
    verified_at: NormalizedUtc
    first_observed_at: NormalizedUtc


class FactComparison(ClosedModel):
    canonical_limit = 1024
    changed_fields: Annotated[
        list[SelectedFieldName],
        BeforeValidator(partial(_sequence, 0, 13)),
        Field(
            min_length=0, max_length=13, json_schema_extra=partial(_schema_constraints, {"minItems": 0, "maxItems": 13})
        ),
    ]
    change_codes: Annotated[
        list[ChangeCode],
        BeforeValidator(partial(_sequence, 0, 7)),
        Field(
            min_length=0, max_length=7, json_schema_extra=partial(_schema_constraints, {"minItems": 0, "maxItems": 7})
        ),
    ]
    blocks_full_releases: ExactBoolean
    blocks_all_published: ExactBoolean


class ReadbackDecision(ClosedModel):
    canonical_limit = 3072
    state: Annotated[
        Literal["valid_identical", "valid_different_facts", "absent", "invalid", "unavailable"],
        BeforeValidator(partial(_exact, str)),
    ]
    record: StoredRecordReference | None
    comparison: FactComparison | None
    reason: ReadbackReason | None


class LocalSaveOutcome(ClosedModel):
    canonical_limit = 2048
    record_kind: ReleaseRecordKind
    event_id: ApplicationUuid
    candidate_id: ApplicationUuid
    candidate_selected_facts_sha256: Sha256
    planned_action: Annotated[
        Literal["reuse_publication", "create_publication", "create_observation", "conditional_observation"],
        BeforeValidator(partial(_exact, str)),
    ]
    save_call: Annotated[
        Literal["not_called", "returned_created", "returned_collided", "raised"], BeforeValidator(partial(_exact, str))
    ]
    outcome: LocalDisposition
    local_state: LocalState
    verified_record: StoredRecordReference | None
    mirror_outcome: Annotated[Literal["unobserved"], BeforeValidator(partial(_literal, "unobserved"))]
    reason: SaveReason | None


class ReleaseEvidenceArtifact(ClosedModel):
    canonical_limit = 65536
    input_limit = 131_072
    input_depth = 12
    input_values = 1_024
    id: ApplicationUuid
    title: Annotated[
        Literal["GitHub release publication", "GitHub release source observation"],
        BeforeValidator(partial(_exact, str)),
    ]
    description: Annotated[
        Literal[
            "Recorded upstream release publication. This does not show patch installation or remediation.",
            "Recorded selected source facts for an existing upstream publication. "
            "The observation clock is retrieval time.",
        ],
        BeforeValidator(partial(_exact, str)),
    ]
    evidence_type: Annotated[Literal["repository_metadata"], BeforeValidator(partial(_literal, "repository_metadata"))]
    source_system: Annotated[
        Literal["github-release-cadence"], BeforeValidator(partial(_literal, "github-release-cadence"))
    ]
    collected_at: CoreUtcWire
    collected_by: Annotated[
        Literal["github-public-releases-2026-03-10"],
        BeforeValidator(partial(_literal, "github-public-releases-2026-03-10")),
    ]
    content: PublicationContent | SourceObservationContent
    content_hash: Sha256
    content_format: Annotated[Literal["json"], BeforeValidator(partial(_literal, "json"))]
    file_path: None
    file_size_bytes: None
    control_mappings: Annotated[
        list[None],
        BeforeValidator(partial(_sequence, 0, 0)),
        Field(
            min_length=0, max_length=0, json_schema_extra=partial(_schema_constraints, {"minItems": 0, "maxItems": 0})
        ),
    ]
    sufficiency: Annotated[Literal["unknown"], BeforeValidator(partial(_literal, "unknown"))]
    sufficiency_rationale: None
    missing_elements: Annotated[
        list[None],
        BeforeValidator(partial(_sequence, 0, 0)),
        Field(
            min_length=0, max_length=0, json_schema_extra=partial(_schema_constraints, {"minItems": 0, "maxItems": 0})
        ),
    ]
    validator_confidence: None
    validated_at: None
    validated_by: None
    expires_at: None
    tags: Annotated[
        list[
            Annotated[
                Literal["upstream-release", "publication", "source-observation"], BeforeValidator(partial(_exact, str))
            ]
        ],
        BeforeValidator(partial(_sequence, 2, 2)),
        Field(
            min_length=2, max_length=2, json_schema_extra=partial(_schema_constraints, {"minItems": 2, "maxItems": 2})
        ),
    ]
    metadata: ReleaseEvidenceMetadata
    version: Annotated[Literal[1], BeforeValidator(partial(_literal, 1))]
    lineage_id: ApplicationUuid
    predecessor_id: None


class PollRequest(ClosedModel):
    canonical_limit = 4_096
    input_limit = 4_096
    input_depth = 8
    input_values = 64
    schema_version: Annotated[
        Literal["release-poll-request-v1"], BeforeValidator(partial(_literal, "release-poll-request-v1"))
    ]
    source_profile: Annotated[
        Literal["github-public-releases-2026-03-10"],
        BeforeValidator(partial(_literal, "github-public-releases-2026-03-10")),
    ]
    owner: Annotated[
        str,
        BeforeValidator(partial(_text, 39, 0, "^[\\x00-\\x7f]*$")),
        Field(
            min_length=0,
            max_length=39,
            pattern="^[\\x00-\\x7f]*$",
            json_schema_extra=partial(
                _schema_constraints, {"minLength": 0, "maxLength": 39, "pattern": "^[\\x00-\\x7f]*$"}
            ),
        ),
    ]
    repository: Annotated[
        str,
        BeforeValidator(partial(_text, 100, 0, "^[\\x00-\\x7f]*$")),
        Field(
            min_length=0,
            max_length=100,
            pattern="^[\\x00-\\x7f]*$",
            json_schema_extra=partial(
                _schema_constraints, {"minLength": 0, "maxLength": 100, "pattern": "^[\\x00-\\x7f]*$"}
            ),
        ),
    ]
    channel: Annotated[Literal["full_releases", "all_published"], BeforeValidator(partial(_exact, str))]
    persist: ExactBoolean


class PollScope(ClosedModel):
    identity_version: Annotated[
        Literal["evidentia.release-publication.v1"],
        BeforeValidator(partial(_literal, "evidentia.release-publication.v1")),
    ]
    source_profile: Annotated[
        Literal["github-public-releases-2026-03-10"],
        BeforeValidator(partial(_literal, "github-public-releases-2026-03-10")),
    ]
    source_host: Annotated[Literal["api.github.com"], BeforeValidator(partial(_literal, "api.github.com"))]
    canonical_owner: Annotated[
        str,
        BeforeValidator(partial(_text, 39, 0, "^[\\x00-\\x7f]*$")),
        Field(
            min_length=0,
            max_length=39,
            pattern="^[\\x00-\\x7f]*$",
            json_schema_extra=partial(
                _schema_constraints, {"minLength": 0, "maxLength": 39, "pattern": "^[\\x00-\\x7f]*$"}
            ),
        ),
    ]
    canonical_repository: Annotated[
        str,
        BeforeValidator(partial(_text, 100, 0, "^[\\x00-\\x7f]*$")),
        Field(
            min_length=0,
            max_length=100,
            pattern="^[\\x00-\\x7f]*$",
            json_schema_extra=partial(
                _schema_constraints, {"minLength": 0, "maxLength": 100, "pattern": "^[\\x00-\\x7f]*$"}
            ),
        ),
    ]
    channel: Annotated[Literal["full_releases", "all_published"], BeforeValidator(partial(_exact, str))]


class RunClocks(ClosedModel):
    poll_id: PollUuid
    started_at: NormalizedUtc
    traversal_completed_at: NormalizedUtc | None
    completed_at: NormalizedUtc


class SourceTimeView(ClosedModel):
    classification: Annotated[
        Literal[
            "absent",
            "unsupported_syntax",
            "unsupported_year",
            "invalid_calendar",
            "unsupported_leap_second",
            "unsupported_precision",
            "utc_out_of_range",
            "normalized",
        ],
        BeforeValidator(partial(_exact, str)),
    ]
    normalized_utc: NormalizedUtc | None


class RowMetadata(ClosedModel):
    row_index: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 999)),
        Field(ge=0, le=999, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 999})),
    ]
    page_index: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 9)),
        Field(ge=0, le=9, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 9})),
    ]
    record_index: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 99)),
        Field(ge=0, le=99, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 99})),
    ]
    event_index: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 999)),
        Field(ge=0, le=999, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 999})),
    ]
    selected_facts_sha256: Sha256
    source_time: SourceTimeView
    initial_publication_eligible: ExactBoolean
    eligibility_reasons: Annotated[
        list[
            Annotated[
                Literal[
                    "draft",
                    "prerelease_excluded",
                    "publication_time_absent",
                    "publication_time_unsupported",
                    "publication_time_future",
                ],
                BeforeValidator(partial(_exact, str)),
            ]
        ],
        BeforeValidator(partial(_sequence, 0, 5)),
        Field(
            min_length=0, max_length=5, json_schema_extra=partial(_schema_constraints, {"minItems": 0, "maxItems": 5})
        ),
    ]


class RowOccurrence(ClosedModel):
    metadata: RowMetadata
    selected: SelectedReleaseFacts


class PageLedger(ClosedModel):
    page_index: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 9)),
        Field(ge=0, le=9, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 9})),
    ]
    page_ordinal: Annotated[
        int,
        BeforeValidator(partial(_number, 1, 10)),
        Field(ge=1, le=10, json_schema_extra=partial(_schema_constraints, {"minimum": 1, "maximum": 10})),
    ]
    page_number: Annotated[
        int,
        BeforeValidator(partial(_number, 1, 9007199254740991)),
        Field(
            ge=1,
            le=9007199254740991,
            json_schema_extra=partial(_schema_constraints, {"minimum": 1, "maximum": 9007199254740991}),
        ),
    ]
    http_status: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 100, 599)),
            Field(ge=100, le=599, json_schema_extra=partial(_schema_constraints, {"minimum": 100, "maximum": 599})),
        ]
        | None
    )
    retrieved_at: NormalizedUtc | None
    raw_bytes_observed: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 4259840)),
        Field(ge=0, le=4259840, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 4259840})),
    ]
    decoded_bytes_observed: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 4259840)),
        Field(ge=0, le=4259840, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 4259840})),
    ]
    raw_body_complete: ExactBoolean
    decoded_body_complete: ExactBoolean
    raw_body_sha256: Sha256 | None
    decoded_body_sha256: Sha256 | None
    link_state: Annotated[Literal["absent", "valid", "invalid", "unavailable"], BeforeValidator(partial(_exact, str))]
    link_values_sha256: Sha256 | None
    first_page: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 1, 9007199254740991)),
            Field(
                ge=1,
                le=9007199254740991,
                json_schema_extra=partial(_schema_constraints, {"minimum": 1, "maximum": 9007199254740991}),
            ),
        ]
        | None
    )
    previous_page: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 1, 9007199254740991)),
            Field(
                ge=1,
                le=9007199254740991,
                json_schema_extra=partial(_schema_constraints, {"minimum": 1, "maximum": 9007199254740991}),
            ),
        ]
        | None
    )
    next_page: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 1, 9007199254740991)),
            Field(
                ge=1,
                le=9007199254740991,
                json_schema_extra=partial(_schema_constraints, {"minimum": 1, "maximum": 9007199254740991}),
            ),
        ]
        | None
    )
    last_page: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 1, 9007199254740991)),
            Field(
                ge=1,
                le=9007199254740991,
                json_schema_extra=partial(_schema_constraints, {"minimum": 1, "maximum": 9007199254740991}),
            ),
        ]
        | None
    )
    json_value_key_occurrences: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 0, 131073)),
            Field(ge=0, le=131073, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 131073})),
        ]
        | None
    )
    json_depth_observed: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 0, 65)),
            Field(ge=0, le=65, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 65})),
        ]
        | None
    )
    decoded_row_count: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 0, 131071)),
            Field(ge=0, le=131071, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 131071})),
        ]
        | None
    )
    admitted: ExactBoolean
    row_start: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 0, 1000)),
            Field(ge=0, le=1000, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 1000})),
        ]
        | None
    )
    row_count: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 100)),
        Field(ge=0, le=100, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 100})),
    ]
    reason: (
        Annotated[
            Literal[
                "offline_refused",
                "destination_refused",
                "dns_failure",
                "tls_failure",
                "connection_failure",
                "timeout",
                "cleanup_failure",
                "dependency_unavailable",
                "dependency_broken",
                "invalid_response",
                "unsupported_media",
                "unsupported_encoding",
                "unsupported_link",
                "page_limit",
                "row_limit",
                "raw_limit",
                "decoded_limit",
                "json_syntax",
                "json_depth",
                "json_count",
                "json_scalar",
                "source_field",
                "source_conflict",
                "selected_limit",
                "result_limit",
                "clock_invalid",
                "deadline_exceeded",
                "cancelled",
                "redirect_refused",
                "upstream_unauthorized",
                "upstream_forbidden",
                "upstream_not_found",
                "upstream_rate_limited",
                "upstream_server_error",
                "upstream_http_error",
                "store_record_invalid",
                "store_identity_conflict",
                "store_digest_conflict",
                "store_parent_missing",
                "store_parent_conflict",
                "store_changed",
                "store_unavailable",
                "store_limit_exceeded",
                "publication_not_eligible",
                "observation_not_needed",
                "known_parent_absent",
                "save_failed",
                "save_readback_mismatch",
            ],
            BeforeValidator(partial(_exact, str)),
        ]
        | None
    )


class EventGroup(ClosedModel):
    event_index: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 999)),
        Field(ge=0, le=999, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 999})),
    ]
    event_id: ApplicationUuid
    release_id: Annotated[
        int,
        BeforeValidator(partial(_number, 1, 9007199254740991)),
        Field(
            ge=1,
            le=9007199254740991,
            json_schema_extra=partial(_schema_constraints, {"minimum": 1, "maximum": 9007199254740991}),
        ),
    ]
    representative_row_index: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 999)),
        Field(ge=0, le=999, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 999})),
    ]
    occurrence_count: Annotated[
        int,
        BeforeValidator(partial(_number, 1, 1000)),
        Field(ge=1, le=1000, json_schema_extra=partial(_schema_constraints, {"minimum": 1, "maximum": 1000})),
    ]
    stored_state: Annotated[
        Literal["not_observed", "absent", "verified", "conflict", "unavailable"], BeforeValidator(partial(_exact, str))
    ]
    known_observation_count: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 0, 1023)),
            Field(ge=0, le=1023, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 1023})),
        ]
        | None
    )
    current_vs_parent: FactComparison | None
    stored_union_change_codes: Annotated[
        list[
            Annotated[
                Literal[
                    "non_cadence_facts_changed",
                    "publication_literal_changed",
                    "node_id_changed",
                    "publication_instant_changed",
                    "publication_time_unqualified",
                    "draft_changed_to_true",
                    "prerelease_changed",
                ],
                BeforeValidator(partial(_exact, str)),
            ]
        ],
        BeforeValidator(partial(_sequence, 0, 7)),
        Field(
            min_length=0, max_length=7, json_schema_extra=partial(_schema_constraints, {"minItems": 0, "maxItems": 7})
        ),
    ]
    blocks_full_releases: ExactBoolean | None
    blocks_all_published: ExactBoolean | None
    publication_outcome_index: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 0, 1999)),
            Field(ge=0, le=1999, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 1999})),
        ]
        | None
    )
    observation_outcome_index: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 0, 1999)),
            Field(ge=0, le=1999, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 1999})),
        ]
        | None
    )


class DiscoverySummary(ClosedModel):
    status: Annotated[
        Literal[
            "not_requested",
            "not_started",
            "complete",
            "unavailable",
            "changed",
            "limit_exceeded",
            "record_invalid",
            "identity_conflict",
            "deadline_exceeded",
            "cancelled",
        ],
        BeforeValidator(partial(_exact, str)),
    ]
    passes: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2)),
        Field(ge=0, le=2, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2})),
    ]
    root_entries_observed: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 8194)),
        Field(ge=0, le=8194, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 8194})),
    ]
    child_entries_observed: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 32770)),
        Field(ge=0, le=32770, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 32770})),
    ]
    canonical_files_read: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 16386)),
        Field(ge=0, le=16386, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 16386})),
    ]
    raw_file_bytes_observed: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 67108865)),
        Field(ge=0, le=67108865, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 67108865})),
    ]
    release_record_reads_observed: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2049)),
        Field(ge=0, le=2049, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2049})),
    ]
    inventory_sha256: Sha256 | None
    selected_scope_records: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 0, 1024)),
            Field(ge=0, le=1024, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 1024})),
        ]
        | None
    )
    conflicting_events: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 0, 1024)),
            Field(ge=0, le=1024, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 1024})),
        ]
        | None
    )


class PollCounters(ClosedModel):
    attempts: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 10)),
        Field(ge=0, le=10, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 10})),
    ]
    pages_admitted: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 10)),
        Field(ge=0, le=10, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 10})),
    ]
    rows_admitted: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 1000)),
        Field(ge=0, le=1000, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 1000})),
    ]
    unique_source_events: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 1000)),
        Field(ge=0, le=1000, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 1000})),
    ]
    raw_entity_bytes_observed: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 16842752)),
        Field(ge=0, le=16842752, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 16842752})),
    ]
    decoded_entity_bytes_observed: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 16842752)),
        Field(ge=0, le=16842752, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 16842752})),
    ]
    selected_ccompact_bytes_admitted: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 8388608)),
        Field(ge=0, le=8388608, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 8388608})),
    ]
    targeted_record_reads: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 4000)),
        Field(ge=0, le=4000, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 4000})),
    ]
    targeted_raw_bytes_observed: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 67108865)),
        Field(ge=0, le=67108865, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 67108865})),
    ]
    total_store_raw_bytes_observed: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 67108865)),
        Field(ge=0, le=67108865, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 67108865})),
    ]


class OutcomeCounts(ClosedModel):
    created: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2000)),
        Field(ge=0, le=2000, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2000})),
    ]
    already_saved: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2000)),
        Field(ge=0, le=2000, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2000})),
    ]
    existing_different_facts: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2000)),
        Field(ge=0, le=2000, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2000})),
    ]
    present_after_uncertain_save: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2000)),
        Field(ge=0, le=2000, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2000})),
    ]
    not_applicable: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2000)),
        Field(ge=0, le=2000, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2000})),
    ]
    not_attempted: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2000)),
        Field(ge=0, le=2000, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2000})),
    ]
    failed: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2000)),
        Field(ge=0, le=2000, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2000})),
    ]
    indeterminate: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2000)),
        Field(ge=0, le=2000, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2000})),
    ]
    conflict: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2000)),
        Field(ge=0, le=2000, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2000})),
    ]


class PersistenceSummary(ClosedModel):
    requested: ExactBoolean
    state: Annotated[
        Literal["not_requested", "not_started", "complete", "partial", "indeterminate"],
        BeforeValidator(partial(_exact, str)),
    ]
    planned_slots: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2000)),
        Field(ge=0, le=2000, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2000})),
    ]
    attempted_calls: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2000)),
        Field(ge=0, le=2000, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2000})),
    ]
    last_attempted_slot: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 0, 1999)),
            Field(ge=0, le=1999, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 1999})),
        ]
        | None
    )
    outcome_counts: OutcomeCounts
    stop_reason: (
        Annotated[
            Literal[
                "offline_refused",
                "destination_refused",
                "dns_failure",
                "tls_failure",
                "connection_failure",
                "timeout",
                "cleanup_failure",
                "dependency_unavailable",
                "dependency_broken",
                "invalid_response",
                "unsupported_media",
                "unsupported_encoding",
                "unsupported_link",
                "page_limit",
                "row_limit",
                "raw_limit",
                "decoded_limit",
                "json_syntax",
                "json_depth",
                "json_count",
                "json_scalar",
                "source_field",
                "source_conflict",
                "selected_limit",
                "result_limit",
                "clock_invalid",
                "deadline_exceeded",
                "cancelled",
                "redirect_refused",
                "upstream_unauthorized",
                "upstream_forbidden",
                "upstream_not_found",
                "upstream_rate_limited",
                "upstream_server_error",
                "upstream_http_error",
                "store_record_invalid",
                "store_identity_conflict",
                "store_digest_conflict",
                "store_parent_missing",
                "store_parent_conflict",
                "store_changed",
                "store_unavailable",
                "store_limit_exceeded",
                "publication_not_eligible",
                "observation_not_needed",
                "known_parent_absent",
                "save_failed",
                "save_readback_mismatch",
            ],
            BeforeValidator(partial(_exact, str)),
        ]
        | None
    )
    mirror_outcome: Annotated[Literal["unobserved"], BeforeValidator(partial(_literal, "unobserved"))]


class PollResult(ClosedModel):
    schema_version: Annotated[
        Literal["release-poll-result-v1"], BeforeValidator(partial(_literal, "release-poll-result-v1"))
    ]
    request: PollRequest
    request_sha256: Sha256
    scope: PollScope
    clocks: RunClocks
    collection_state: Annotated[Literal["complete", "partial", "unavailable"], BeforeValidator(partial(_exact, str))]
    terminal_reason: (
        Annotated[
            Literal[
                "offline_refused",
                "destination_refused",
                "dns_failure",
                "tls_failure",
                "connection_failure",
                "timeout",
                "cleanup_failure",
                "dependency_unavailable",
                "dependency_broken",
                "invalid_response",
                "unsupported_media",
                "unsupported_encoding",
                "unsupported_link",
                "page_limit",
                "row_limit",
                "raw_limit",
                "decoded_limit",
                "json_syntax",
                "json_depth",
                "json_count",
                "json_scalar",
                "source_field",
                "source_conflict",
                "selected_limit",
                "result_limit",
                "clock_invalid",
                "deadline_exceeded",
                "cancelled",
                "redirect_refused",
                "upstream_unauthorized",
                "upstream_forbidden",
                "upstream_not_found",
                "upstream_rate_limited",
                "upstream_server_error",
                "upstream_http_error",
                "store_record_invalid",
                "store_identity_conflict",
                "store_digest_conflict",
                "store_parent_missing",
                "store_parent_conflict",
                "store_changed",
                "store_unavailable",
                "store_limit_exceeded",
                "publication_not_eligible",
                "observation_not_needed",
                "known_parent_absent",
                "save_failed",
                "save_readback_mismatch",
            ],
            BeforeValidator(partial(_exact, str)),
        ]
        | None
    )
    reasons: Annotated[
        list[
            Annotated[
                Literal[
                    "offline_refused",
                    "destination_refused",
                    "dns_failure",
                    "tls_failure",
                    "connection_failure",
                    "timeout",
                    "cleanup_failure",
                    "dependency_unavailable",
                    "dependency_broken",
                    "invalid_response",
                    "unsupported_media",
                    "unsupported_encoding",
                    "unsupported_link",
                    "page_limit",
                    "row_limit",
                    "raw_limit",
                    "decoded_limit",
                    "json_syntax",
                    "json_depth",
                    "json_count",
                    "json_scalar",
                    "source_field",
                    "source_conflict",
                    "selected_limit",
                    "result_limit",
                    "clock_invalid",
                    "deadline_exceeded",
                    "cancelled",
                    "redirect_refused",
                    "upstream_unauthorized",
                    "upstream_forbidden",
                    "upstream_not_found",
                    "upstream_rate_limited",
                    "upstream_server_error",
                    "upstream_http_error",
                    "store_record_invalid",
                    "store_identity_conflict",
                    "store_digest_conflict",
                    "store_parent_missing",
                    "store_parent_conflict",
                    "store_changed",
                    "store_unavailable",
                    "store_limit_exceeded",
                    "publication_not_eligible",
                    "observation_not_needed",
                    "known_parent_absent",
                    "save_failed",
                    "save_readback_mismatch",
                ],
                BeforeValidator(partial(_exact, str)),
            ]
        ],
        BeforeValidator(partial(_sequence, 0, 32)),
        Field(
            min_length=0, max_length=32, json_schema_extra=partial(_schema_constraints, {"minItems": 0, "maxItems": 32})
        ),
    ]
    counters: PollCounters
    discovery: DiscoverySummary
    persistence: PersistenceSummary
    rows: Annotated[
        list[RowOccurrence],
        BeforeValidator(partial(_sequence, 0, 1000)),
        Field(
            min_length=0,
            max_length=1000,
            json_schema_extra=partial(_schema_constraints, {"minItems": 0, "maxItems": 1000}),
        ),
    ]
    pages: Annotated[
        list[PageLedger],
        BeforeValidator(partial(_sequence, 0, 10)),
        Field(
            min_length=0, max_length=10, json_schema_extra=partial(_schema_constraints, {"minItems": 0, "maxItems": 10})
        ),
    ]
    events: Annotated[
        list[EventGroup],
        BeforeValidator(partial(_sequence, 0, 1000)),
        Field(
            min_length=0,
            max_length=1000,
            json_schema_extra=partial(_schema_constraints, {"minItems": 0, "maxItems": 1000}),
        ),
    ]
    outcomes: Annotated[
        list[LocalSaveOutcome],
        BeforeValidator(partial(_sequence, 0, 2000)),
        Field(
            min_length=0,
            max_length=2000,
            json_schema_extra=partial(_schema_constraints, {"minItems": 0, "maxItems": 2000}),
        ),
    ]
    meaning: Annotated[
        Literal["visible_upstream_release_observation"],
        BeforeValidator(partial(_literal, "visible_upstream_release_observation")),
    ]


class ReleaseError(ClosedModel):
    schema_version: Annotated[Literal["release-error-v1"], BeforeValidator(partial(_literal, "release-error-v1"))]
    code: Annotated[
        Literal[
            "invalid_request",
            "request_limit_exceeded",
            "result_limit_exceeded",
            "unsupported_media",
            "support_unavailable",
            "support_broken",
            "authority_unavailable",
            "operation_failed",
            "persistence_outcome_unavailable",
        ],
        BeforeValidator(partial(_exact, str)),
    ]
    message: Annotated[
        Literal[
            "The release request is invalid.",
            "The release request exceeds its limit.",
            "The release result exceeds its limit.",
            "The release request media type is unsupported.",
            "Release support is unavailable.",
            "Release support failed.",
            "Release authority is unavailable.",
            "The release operation failed.",
            "The release deadline expired after a save was attempted. "
            "Persistence may have occurred. Inspect local records before retrying.",
        ],
        BeforeValidator(partial(_exact, str)),
    ]


class ReleaseSeriesRequest(ClosedModel):
    canonical_limit = 4_096
    input_limit = 4_096
    input_depth = 8
    input_values = 64
    schema_version: Annotated[
        Literal["release-series-request-v1"], BeforeValidator(partial(_literal, "release-series-request-v1"))
    ]
    source_profile: Annotated[
        Literal["github-public-releases-2026-03-10"],
        BeforeValidator(partial(_literal, "github-public-releases-2026-03-10")),
    ]
    owner: Annotated[
        str,
        BeforeValidator(partial(_text, 39, 1, r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")),
        Field(
            min_length=1,
            max_length=39,
            json_schema_extra=partial(_schema_constraints, {"minLength": 1, "maxLength": 39}),
        ),
    ]
    repository: Annotated[
        str,
        BeforeValidator(partial(_text, 100, 1, r"[A-Za-z0-9_.-]+")),
        Field(
            min_length=1,
            max_length=100,
            json_schema_extra=partial(_schema_constraints, {"minLength": 1, "maxLength": 100}),
        ),
    ]
    channel: ReleaseChannel
    window_start: WindowUtc
    window_end: WindowUtc
    interval_days: Annotated[
        int,
        BeforeValidator(partial(_number, 1, 3660)),
        Field(ge=1, le=3660, json_schema_extra=partial(_schema_constraints, {"minimum": 1, "maximum": 3660})),
    ]
    tolerance_days: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 3660)),
        Field(ge=0, le=3660, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 3660})),
    ]


class SeriesScope(ClosedModel):
    source_profile: Annotated[
        Literal["github-public-releases-2026-03-10"],
        BeforeValidator(partial(_literal, "github-public-releases-2026-03-10")),
    ]
    source_host: Annotated[Literal["api.github.com"], BeforeValidator(partial(_literal, "api.github.com"))]
    canonical_owner: CanonicalRepositoryToken256
    canonical_repository: CanonicalRepositoryToken256
    channel: ReleaseChannel


class DiscoveryResult(ClosedModel):
    status: Annotated[
        Literal[
            "complete",
            "unavailable",
            "changed",
            "limit_exceeded",
            "record_invalid",
            "identity_conflict",
            "deadline_exceeded",
        ],
        BeforeValidator(partial(_exact, str)),
    ]
    passes: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2)),
        Field(ge=0, le=2, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2})),
    ]
    root_entries_observed: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 8194)),
        Field(ge=0, le=8194, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 8194})),
    ]
    child_entries_observed: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 32770)),
        Field(ge=0, le=32770, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 32770})),
    ]
    canonical_files_read: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 16386)),
        Field(ge=0, le=16386, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 16386})),
    ]
    raw_file_bytes_observed: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 67108865)),
        Field(ge=0, le=67108865, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 67108865})),
    ]
    release_records_observed: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2049)),
        Field(ge=0, le=2049, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2049})),
    ]
    inventory_sha256: Sha256 | None
    meaning: Annotated[
        Literal["bounded_recorded_store_observation"],
        BeforeValidator(partial(_literal, "bounded_recorded_store_observation")),
    ]


class RecordReference(ClosedModel):
    canonical_limit = 1_024
    artifact_id: ApplicationUuid
    record_kind: ReleaseRecordKind
    event_index: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2047)),
        Field(ge=0, le=2047, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2047})),
    ]
    version: Annotated[Literal[1], BeforeValidator(partial(_literal, 1))]
    selected_facts_sha256: Sha256
    content_sha256: Sha256
    stored_file_sha256: Sha256
    first_observed_at: NormalizedUtc


SeriesEventReason = Annotated[
    Literal[
        "prerelease_excluded",
        "node_id_changed",
        "publication_instant_changed",
        "publication_time_unqualified",
        "draft_changed_to_true",
        "prerelease_changed",
    ],
    BeforeValidator(partial(_exact, str)),
]
SeriesResultReason = Annotated[
    Literal[
        "gap_exceeds_allowed",
        "insufficient_events",
        "source_conflict",
        "store_unavailable",
        "store_changed",
        "store_limit_exceeded",
        "store_record_invalid",
        "store_identity_conflict",
        "deadline_exceeded",
    ],
    BeforeValidator(partial(_exact, str)),
]


class SeriesEvent(ClosedModel):
    canonical_limit = 1_536
    event_id: ApplicationUuid
    release_id: ReleaseId
    publication_record_index: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2047)),
        Field(ge=0, le=2047, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2047})),
    ]
    observation_count: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 2047)),
        Field(ge=0, le=2047, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2047})),
    ]
    published_at_literal: SourceTimestamp128
    published_at: NormalizedUtc
    in_window: ExactBoolean
    eligibility: Annotated[Literal["eligible", "channel_excluded", "conflict"], BeforeValidator(partial(_exact, str))]
    reasons: Annotated[
        list[SeriesEventReason],
        BeforeValidator(partial(_sequence, 0, 16)),
        Field(max_length=16, json_schema_extra=partial(_schema_constraints, {"maxItems": 16})),
    ]


class SeriesGap(ClosedModel):
    canonical_limit = 768
    start_at: NormalizedUtc
    end_at: NormalizedUtc
    left_event_index: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 0, 2047)),
            Field(ge=0, le=2047, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2047})),
        ]
        | None
    )
    right_event_index: (
        Annotated[
            int,
            BeforeValidator(partial(_number, 0, 2047)),
            Field(ge=0, le=2047, json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 2047})),
        ]
        | None
    )
    boundary: Annotated[Literal["start", "between", "end"], BeforeValidator(partial(_exact, str))]
    elapsed_microseconds: Annotated[
        int,
        BeforeValidator(partial(_number, 0, 3162240000000000)),
        Field(
            ge=0,
            le=3162240000000000,
            json_schema_extra=partial(_schema_constraints, {"minimum": 0, "maximum": 3162240000000000}),
        ),
    ]
    allowed_microseconds: Annotated[
        int,
        BeforeValidator(partial(_number, 86400000000, 632448000000000)),
        Field(
            ge=86400000000,
            le=632448000000000,
            json_schema_extra=partial(_schema_constraints, {"minimum": 86400000000, "maximum": 632448000000000}),
        ),
    ]
    exceeds_allowed: ExactBoolean


class ReleaseSeriesResult(ClosedModel):
    schema_version: Annotated[
        Literal["release-series-result-v1"], BeforeValidator(partial(_literal, "release-series-result-v1"))
    ]
    request: ReleaseSeriesRequest
    request_sha256: Sha256
    scope: SeriesScope
    evaluation_at: NormalizedUtc
    completed_at: NormalizedUtc
    discovery: DiscoveryResult
    state: Annotated[
        Literal["continuous", "gapped", "insufficient", "unavailable", "conflict"],
        BeforeValidator(partial(_exact, str)),
    ]
    reasons: Annotated[
        list[SeriesResultReason],
        BeforeValidator(partial(_sequence, 0, 32)),
        Field(max_length=32, json_schema_extra=partial(_schema_constraints, {"maxItems": 32})),
    ]
    records: Annotated[
        list[RecordReference],
        BeforeValidator(partial(_sequence, 0, 2048)),
        Field(max_length=2048, json_schema_extra=partial(_schema_constraints, {"maxItems": 2048})),
    ]
    events: Annotated[
        list[SeriesEvent],
        BeforeValidator(partial(_sequence, 0, 2048)),
        Field(max_length=2048, json_schema_extra=partial(_schema_constraints, {"maxItems": 2048})),
    ]
    gaps: Annotated[
        list[SeriesGap],
        BeforeValidator(partial(_sequence, 0, 2049)),
        Field(max_length=2049, json_schema_extra=partial(_schema_constraints, {"maxItems": 2049})),
    ]
    meaning: Annotated[
        Literal["recorded_upstream_publication_spacing"],
        BeforeValidator(partial(_literal, "recorded_upstream_publication_spacing")),
    ]


for _declared in (
    SelectedReleaseFacts,
    EventKey,
    SourcePublicationTime,
    FirstObservation,
    ParentPublication,
    PublicationContent,
    SourceObservationContent,
    ReleaseEvidenceMetadata,
    StoredRecordReference,
    FactComparison,
    ReadbackDecision,
    LocalSaveOutcome,
    ReleaseEvidenceArtifact,
    PollRequest,
    PollScope,
    RunClocks,
    SourceTimeView,
    RowMetadata,
    RowOccurrence,
    PageLedger,
    EventGroup,
    DiscoverySummary,
    PollCounters,
    OutcomeCounts,
    PersistenceSummary,
    PollResult,
    ReleaseError,
    ReleaseSeriesRequest,
    SeriesScope,
    DiscoveryResult,
    RecordReference,
    SeriesEvent,
    SeriesGap,
    ReleaseSeriesResult,
):
    _MODEL_TYPES[id(_declared)] = _declared
for _resolved_model in tuple(_MODEL_TYPES.values()):
    _resolved_model.model_rebuild()
