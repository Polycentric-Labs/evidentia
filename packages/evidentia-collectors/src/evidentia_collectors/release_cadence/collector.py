"""One finite release poll with immutable source authority and explicit saving."""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from evidentia_core.release_cadence._contracts import (
    CHANGE_CODES,
    LocalSaveOutcome,
    PollRequest,
    PollResult,
    native_model,
    publication_eligibility,
)
from evidentia_core.release_cadence._identity import (
    build_observation,
    build_publication,
    compare_facts,
    event_identity,
    event_tuple,
    fact_digest,
    observation_identity,
    to_core_artifact,
)
from evidentia_core.release_cadence._json import canonical_bytes
from evidentia_core.release_cadence._limits import (
    ARTIFACT_BYTES,
    RESULT_BYTES,
    SOURCE_HOST,
    SOURCE_PROFILE,
    Budget,
    ReleaseFailure,
    _capture_invocation,
    _Invocation,
    _PersistenceAuthority,
    start_budget,
)
from evidentia_core.release_cadence._source import canonical_repository
from evidentia_core.release_cadence._time import parse_window_time, utc_text
from pydantic import ValidationError

_OUTCOMES = (
    "created",
    "already_saved",
    "existing_different_facts",
    "present_after_uncertain_save",
    "not_applicable",
    "not_attempted",
    "failed",
    "indeterminate",
    "conflict",
)
_DISCOVERY_REASONS = {
    "unavailable": "store_unavailable",
    "changed": "store_changed",
    "limit_exceeded": "store_limit_exceeded",
    "record_invalid": "store_record_invalid",
    "identity_conflict": "store_identity_conflict",
    "deadline_exceeded": "deadline_exceeded",
    "cancelled": "cancelled",
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _restore(raw: bytes, maximum: int, budget: Budget) -> Any:
    """Restore only this lifecycle's retained canonical byte snapshots."""
    budget.check()
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise ReleaseFailure("result_limit")
    value = json.loads(raw)
    budget.check()
    return value


def _not_discovered(status: str) -> dict[str, Any]:
    return {
        "status": status,
        "passes": 0,
        "root_entries_observed": 0,
        "child_entries_observed": 0,
        "canonical_files_read": 0,
        "raw_file_bytes_observed": 0,
        "release_record_reads_observed": 0,
        "inventory_sha256": None,
        "selected_scope_records": None,
        "conflicting_events": None,
    }


def _source_tables(
    occurrences: list[dict[str, Any]], request: dict[str, Any], completion: str | None, budget: Budget
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    owner, repository = canonical_repository(request["owner"], request["repository"])
    identities = {
        occurrence["selected"]["id"]: cast(
            dict[str, Any], event_identity(owner, repository, occurrence["selected"]["id"])
        )
        for occurrence in occurrences
    }
    ordered = sorted(identities, key=lambda identifier: tuple(event_tuple(identities[identifier]["event_key"])))
    indexes = {identifier: index for index, identifier in enumerate(ordered)}
    rows: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    members: dict[int, list[int]] = {identifier: [] for identifier in ordered}
    for index, occurrence in enumerate(occurrences):
        budget.check()
        selected = occurrence["selected"]
        identifier = selected["id"]
        time_view, reasons, eligible = publication_eligibility(selected, request["channel"], completion)
        rows.append(
            {
                "metadata": {
                    "row_index": index,
                    "page_index": occurrence["page_index"],
                    "record_index": occurrence["record_index"],
                    "event_index": indexes[identifier],
                    "selected_facts_sha256": fact_digest(selected, budget=budget),
                    "source_time": time_view,
                    "initial_publication_eligible": eligible,
                    "eligibility_reasons": reasons,
                },
                "selected": selected,
            }
        )
        members[identifier].append(index)
    for index, identifier in enumerate(ordered):
        positions = members[identifier]
        events.append(
            {
                "event_index": index,
                "event_id": identities[identifier]["event_id"],
                "release_id": identifier,
                "representative_row_index": positions[0],
                "occurrence_count": len(positions),
                "stored_state": "not_observed",
                "known_observation_count": None,
                "current_vs_parent": None,
                "stored_union_change_codes": [],
                "blocks_full_releases": None,
                "blocks_all_published": None,
                "publication_outcome_index": None,
                "observation_outcome_index": None,
            }
        )
    return rows, events


def _base(request_bytes: bytes, traversal: Any, started: datetime, poll_id: str, budget: Budget) -> dict[str, Any]:
    request = _restore(request_bytes, 4096, budget)
    occurrences = _restore(traversal.occurrences_bytes, RESULT_BYTES, budget)
    pages = _restore(traversal.pages_bytes, 122896, budget)
    rows, events = _source_tables(occurrences, request, traversal.completed_at, budget)
    owner, repository = canonical_repository(request["owner"], request["repository"])
    admitted = sum(page["admitted"] for page in pages)
    return {
        "schema_version": "release-poll-result-v1",
        "request": request,
        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "scope": {
            "identity_version": "evidentia.release-publication.v1",
            "source_profile": SOURCE_PROFILE,
            "source_host": SOURCE_HOST,
            "canonical_owner": owner,
            "canonical_repository": repository,
            "channel": request["channel"],
        },
        "clocks": {
            "poll_id": poll_id,
            "started_at": utc_text(started),
            "traversal_completed_at": traversal.completed_at,
            "completed_at": utc_text(started),
        },
        "collection_state": "complete" if traversal.reason is None else "partial" if admitted else "unavailable",
        "terminal_reason": traversal.reason,
        "reasons": [] if traversal.reason is None else [traversal.reason],
        "counters": {
            "attempts": traversal.attempts,
            "pages_admitted": admitted,
            "rows_admitted": len(rows),
            "unique_source_events": len(events),
            "raw_entity_bytes_observed": traversal.raw_bytes,
            "decoded_entity_bytes_observed": traversal.decoded_bytes,
            "selected_ccompact_bytes_admitted": traversal.selected_bytes,
            "targeted_record_reads": 0,
            "targeted_raw_bytes_observed": 0,
            "total_store_raw_bytes_observed": 0,
        },
        "discovery": _not_discovered("not_started" if request["persist"] else "not_requested"),
        "persistence": {
            "requested": request["persist"],
            "state": "not_started" if request["persist"] else "not_requested",
            "planned_slots": 0,
            "attempted_calls": 0,
            "last_attempted_slot": None,
            "outcome_counts": {name: 0 for name in _OUTCOMES},
            "stop_reason": traversal.reason if request["persist"] else None,
            "mirror_outcome": "unobserved",
        },
        "rows": rows,
        "pages": pages,
        "events": events,
        "outcomes": [],
        "meaning": "visible_upstream_release_observation",
    }


def _first(base: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    row = base["rows"][event["representative_row_index"]]
    page = base["pages"][row["metadata"]["page_index"]]
    return {
        "poll_id": base["clocks"]["poll_id"],
        "request_sha256": base["request_sha256"],
        "requested_owner": base["request"]["owner"],
        "requested_repository": base["request"]["repository"],
        "channel": base["request"]["channel"],
        "page_ordinal": page["page_ordinal"],
        "page_number": page["page_number"],
        "record_index": row["metadata"]["record_index"],
        "retrieved_at": page["retrieved_at"],
        "traversal_completed_at": base["clocks"]["traversal_completed_at"],
        "response_raw_sha256": page["raw_body_sha256"],
        "response_decoded_sha256": page["decoded_body_sha256"],
    }


def _outcome(event_id: str, candidate_id: str, selected_sha: str, *, observation: bool, action: str) -> dict[str, Any]:
    return {
        "record_kind": "release_source_observation" if observation else "release_publication",
        "event_id": event_id,
        "candidate_id": candidate_id,
        "candidate_selected_facts_sha256": selected_sha,
        "planned_action": action,
        "save_call": "not_called",
        "outcome": "not_attempted",
        "local_state": "not_attempted",
        "verified_record": None,
        "mirror_outcome": "unobserved",
        "reason": "deadline_exceeded",
    }


def _skipped(value: dict[str, Any], reason: str) -> dict[str, Any]:
    return {**value, "outcome": "not_applicable", "reason": reason}


def _captured_record(record: Any) -> Any:
    """Copy the exact immutable descriptor observation before lending a model."""
    from evidentia_core.release_cadence._store import VerifiedRecord

    if type(record) is not VerifiedRecord:
        raise ReleaseFailure("store_record_invalid")
    if any(type(part) is not bytes for part in (record.raw, record.artifact_bytes)):
        raise ReleaseFailure("store_record_invalid")
    return VerifiedRecord(
        record.relative_path,
        record.raw,
        record.artifact_bytes,
        record.stored_file_sha256,
        record.physical,
        record.verified_at,
    )


@dataclass(frozen=True, slots=True)
class _Plan:
    event_index: int
    candidate: bytes | None
    parent: Any
    prior_observation: Any


def _reused(outcome: dict[str, Any], record: Any) -> dict[str, Any]:
    from evidentia_core.release_cadence._store import record_reference

    reference = record_reference(_captured_record(record))
    return {
        **outcome,
        "candidate_id": reference["artifact_id"],
        "candidate_selected_facts_sha256": reference["selected_facts_sha256"],
        "outcome": "already_saved",
        "local_state": "local_verified",
        "verified_record": reference,
        "reason": None,
    }


def _bind_parent(event: dict[str, Any], selected: dict[str, Any], parent: Any, observations: list[Any]) -> None:
    original = _captured_record(parent).native()
    parent_facts = original["content"]["selected_facts"]
    comparison = compare_facts(parent_facts, selected)
    codes = set(cast(list[str], comparison["change_codes"]))
    for record in observations:
        native = _captured_record(record).native()
        codes.update(cast(list[str], compare_facts(parent_facts, native["content"]["selected_facts"])["change_codes"]))
    ordered = [code for code in CHANGE_CODES if code in codes]
    material = any(code in codes for code in CHANGE_CODES[2:6])
    event.update(
        {
            "stored_state": "verified",
            "current_vs_parent": comparison,
            "stored_union_change_codes": ordered,
            "blocks_all_published": material,
            "blocks_full_releases": material or "prerelease_changed" in codes,
        }
    )


def _candidate(selected: dict[str, Any], first: dict[str, Any], parent: Any, budget: Budget) -> bytes:
    """Bind a factory result to source and parent bytes captured before the call."""
    from evidentia_core.release_cadence._identity import validate_artifact, verify_parent

    selected_bytes = canonical_bytes(selected, 16384, budget=budget)
    first_bytes = canonical_bytes(first, 4096, budget=budget)
    parent_bytes = None if parent is None else _captured_record(parent).artifact_bytes
    deadline = budget.deadline
    loan_selected = _restore(selected_bytes, 16384, budget)
    loan_first = _restore(first_bytes, 4096, budget)
    if parent_bytes is None:
        proposed = build_publication(loan_selected, loan_first, budget=budget)
    else:
        proposed = build_observation(
            loan_selected,
            loan_first,
            _restore(parent_bytes, ARTIFACT_BYTES, budget),
            budget=budget,
        )
    if type(budget.deadline) is not float or budget.deadline != deadline:
        raise ReleaseFailure("clock_invalid")
    budget.check()
    checked = cast(dict[str, Any], validate_artifact(proposed, budget=budget))
    content = checked["content"]
    if (
        canonical_bytes(content["selected_facts"], 16384, budget=budget) != selected_bytes
        or canonical_bytes(content["first_observation"], 4096, budget=budget) != first_bytes
        or content["record_kind"] != ("release_publication" if parent_bytes is None else "release_source_observation")
    ):
        raise ReleaseFailure("operation_failed")
    if parent_bytes is not None:
        verify_parent(checked, _restore(parent_bytes, ARTIFACT_BYTES, budget), budget=budget)
    return canonical_bytes(checked, ARTIFACT_BYTES, budget=budget)


def _seal_result(
    base_bytes: bytes,
    state_bytes: bytes,
    completed: str,
    budget: Budget,
    check: Callable[[int], None],
) -> bytes:
    """Validate a single wire against immutable authority without rerendering."""
    base = _restore(base_bytes, RESULT_BYTES, budget)
    state = _restore(state_bytes, RESULT_BYTES, budget)
    candidate = _render(
        base,
        state["events"],
        state["outcomes"],
        state["discovery"],
        state["targeted_reads"],
        state["targeted_bytes"],
        state["stop"],
        completed,
    )
    wire = canonical_bytes(candidate, RESULT_BYTES, budget=budget)
    checked = PollResult.model_validate_json(wire)
    check(0)
    actual = cast(dict[str, Any], native_model(checked))
    if canonical_bytes(actual, RESULT_BYTES, budget=budget) != wire:
        raise ReleaseFailure("operation_failed")
    # Renderer arguments are never read as authority after that call.
    expected_base = _restore(base_bytes, RESULT_BYTES, budget)
    expected_state = _restore(state_bytes, RESULT_BYTES, budget)
    changed = {"events", "outcomes", "discovery", "clocks", "counters", "persistence", "reasons"}
    for name in expected_base.keys() - changed:
        if canonical_bytes(actual[name], RESULT_BYTES, budget=budget) != canonical_bytes(
            expected_base[name], RESULT_BYTES, budget=budget
        ):
            raise ReleaseFailure("operation_failed")
    for name in ("events", "outcomes", "discovery"):
        if canonical_bytes(actual[name], RESULT_BYTES, budget=budget) != canonical_bytes(
            expected_state[name], RESULT_BYTES, budget=budget
        ):
            raise ReleaseFailure("operation_failed")
    if actual["clocks"] != {**expected_base["clocks"], "completed_at": completed}:
        raise ReleaseFailure("operation_failed")
    expected_counters = {
        **expected_base["counters"],
        "targeted_record_reads": expected_state["targeted_reads"],
        "targeted_raw_bytes_observed": expected_state["targeted_bytes"],
        "total_store_raw_bytes_observed": expected_state["discovery"]["raw_file_bytes_observed"]
        + expected_state["targeted_bytes"],
    }
    if actual["counters"] != expected_counters or actual["persistence"]["stop_reason"] != expected_state["stop"]:
        raise ReleaseFailure("operation_failed")
    check(0)
    return wire


def _prepare_plans(
    base: dict[str, Any], records: tuple[Any, ...], budget: Budget
) -> tuple[list[_Plan], list[dict[str, Any]], list[dict[str, Any]]]:
    by_id = {record.native()["id"]: _captured_record(record) for record in records}
    events = cast(list[dict[str, Any]], _restore(canonical_bytes(base["events"], RESULT_BYTES), RESULT_BYTES, budget))
    plans: list[_Plan] = []
    outcomes: list[dict[str, Any]] = []
    for event in events:
        budget.check(15)
        index = event["event_index"]
        selected = base["rows"][event["representative_row_index"]]["selected"]
        source_sha = fact_digest(selected, budget=budget)
        identity = cast(
            dict[str, Any], event_identity(base["request"]["owner"], base["request"]["repository"], selected["id"])
        )
        identifier = identity["event_id"]
        observation_id = observation_identity(identity["event_key"], source_sha)
        parent = by_id.get(identifier)
        variants = [
            record
            for record in records
            if record.native()["content"]["event_id"] == identifier
            and record.native()["content"]["record_kind"] == "release_source_observation"
        ]
        known_observation = by_id.get(observation_id)
        event["known_observation_count"] = len(variants)
        event["publication_outcome_index"] = len(outcomes)
        event["observation_outcome_index"] = len(outcomes) + 1
        first = _first(base, event)
        pub = _outcome(
            identifier,
            identifier,
            source_sha,
            observation=False,
            action="reuse_publication" if parent is not None else "create_publication",
        )
        obs = _outcome(
            identifier,
            observation_id,
            source_sha,
            observation=True,
            action="create_observation" if parent is not None else "conditional_observation",
        )
        candidate = observation = None
        if parent is not None:
            _bind_parent(event, selected, parent, variants)
            pub = _reused(pub, parent)
            if parent.native()["content"]["selected_facts"] == selected:
                obs = _skipped(obs, "observation_not_needed")
            else:
                observation = _candidate(selected, first, parent, budget)
                if known_observation is not None:
                    # Complete discovery already verified its immutable parent.
                    if known_observation.native()["content"]["selected_facts"] != selected:
                        raise ReleaseFailure("store_digest_conflict")
                    obs = _reused(obs, known_observation)
        else:
            event.update(
                {
                    "stored_state": "absent",
                    "current_vs_parent": None,
                    "stored_union_change_codes": [],
                    "blocks_full_releases": False,
                    "blocks_all_published": False,
                }
            )
            if base["rows"][event["representative_row_index"]]["metadata"]["initial_publication_eligible"]:
                candidate = _candidate(selected, first, None, budget)
            else:
                pub = _skipped(pub, "publication_not_eligible")
                obs = _skipped(obs, "known_parent_absent")
        plans.extend((_Plan(index, candidate, parent, None), _Plan(index, observation, parent, known_observation)))
        outcomes.extend((pub, obs))
        for value in (pub, obs):
            LocalSaveOutcome.model_validate(value)
            canonical_bytes(value, 2048, budget=budget)
    return plans, events, outcomes


def _persist(
    base: dict[str, Any],
    store_root: object,
    budget: Budget,
    check: Callable[[int], None],
    persistence: _PersistenceAuthority,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], int, int, str | None]:
    from evidentia_core.release_cadence import _store

    retained_base = canonical_bytes(base, RESULT_BYTES, budget=budget)
    root = _store.lexical_store_root(store_root)
    snapshot = _store.discover(root, base["request"]["owner"], base["request"]["repository"], budget, reserve=15)
    summary = cast(dict[str, Any], snapshot.summary())
    discovery = {
        "status": summary["status"],
        "passes": summary["passes"],
        "root_entries_observed": summary["root_entries_observed"],
        "child_entries_observed": summary["child_entries_observed"],
        "canonical_files_read": summary["canonical_files_read"],
        "raw_file_bytes_observed": summary["raw_file_bytes_observed"],
        "release_record_reads_observed": summary["release_records_observed"],
        "inventory_sha256": summary["inventory_sha256"],
        "selected_scope_records": len(snapshot.records) if summary["status"] == "complete" else None,
        "conflicting_events": 0 if summary["status"] == "complete" else None,
    }
    if summary["status"] != "complete":
        events = _restore(canonical_bytes(base["events"], RESULT_BYTES), RESULT_BYTES, budget)
        for event in events:
            event["stored_state"] = "unavailable"
        return events, [], discovery, 0, 0, _DISCOVERY_REASONS[summary["status"]]
    try:
        plans, events, outcomes = _prepare_plans(base, snapshot.records, budget)
    except ReleaseFailure as error:
        if error.reason != "deadline_exceeded":
            raise
        check(0)
        unfinished = _restore(retained_base, RESULT_BYTES, budget)["events"]
        for event in unfinished:
            event["stored_state"] = "unavailable"
        return unfinished, [], discovery, 0, 0, error.reason
    ledger = snapshot.ledger
    before_bytes = ledger.consumed
    binding = snapshot.binding
    if binding is None:
        raise ReleaseFailure("store_unavailable")
    stop: str | None = None
    parents = {record.native()["id"]: _captured_record(record) for record in snapshot.records}
    # Validate the complete no-call refusal envelope before any irreversible call.
    provisional_state = canonical_bytes(
        {
            "events": events,
            "outcomes": outcomes,
            "discovery": discovery,
            "targeted_reads": 0,
            "targeted_bytes": 0,
            "stop": "deadline_exceeded",
        },
        RESULT_BYTES,
        budget=budget,
    )
    _seal_result(retained_base, provisional_state, utc_text(_utc_now()), budget, check)
    persistence.prepare(tuple(canonical_bytes(value, 2048, budget=budget) for value in outcomes))
    try:
        check(15)
        for slot, plan in enumerate(plans):
            outcome = outcomes[slot]
            if outcome["outcome"] in {"already_saved", "not_applicable"}:
                continue
            event = events[plan.event_index]
            selected = base["rows"][event["representative_row_index"]]["selected"]
            is_observation = outcome["record_kind"] == "release_source_observation"
            candidate = plan.candidate
            parent = parents.get(event["event_id"])
            if is_observation and candidate is None:
                if parent is None:
                    outcomes[slot] = _skipped(outcome, "known_parent_absent")
                    persistence.record(slot, canonical_bytes(outcomes[slot], 2048, budget=budget))
                    continue
                if parent.native()["content"]["selected_facts"] == selected:
                    outcomes[slot] = _skipped(outcome, "observation_not_needed")
                    persistence.record(slot, canonical_bytes(outcomes[slot], 2048, budget=budget))
                    continue
                candidate = _candidate(selected, _first(base, event), parent, budget)
            if candidate is None:
                raise ReleaseFailure("store_record_invalid")
            check(0)
            ledger.reserve_readback(observation=is_observation)
            try:
                check(0 if any(item["save_call"] != "not_called" for item in outcomes) else 15)
                binding = _store.prepare_write_root(binding, budget)
                _store.admit_save_target(binding, outcome["candidate_id"], budget)
                native = _restore(candidate, ARTIFACT_BYTES, budget)
                core = to_core_artifact(native, budget=budget)
                check(0 if any(item["save_call"] != "not_called" for item in outcomes) else 15)
                call = "raised"
                try:
                    returned = persistence.save(slot, core, binding.path)
                    call = "returned_created" if returned.state == "created" else "returned_collided"
                except Exception:
                    call = "raised"
                finally:
                    outcomes[slot] = {**outcome, "save_call": call}
                check(0)
                outcome = outcomes[slot]
                verified = _store.readback(
                    binding,
                    outcome["candidate_id"],
                    ledger,
                    budget,
                    expected_parent_bytes=parent.artifact_bytes if is_observation and parent is not None else None,
                )
                if verified is None:
                    if call == "raised":
                        outcomes[slot] = {
                            **outcome,
                            "outcome": "failed",
                            "local_state": "local_absent",
                            "reason": "save_failed",
                        }
                        stop = "save_failed"
                    else:
                        outcomes[slot] = {
                            **outcome,
                            "outcome": "conflict",
                            "local_state": "local_conflict",
                            "reason": "save_readback_mismatch",
                        }
                        stop = "save_readback_mismatch"
                else:
                    actual = cast(dict[str, Any], verified.native())
                    expected = _restore(candidate, ARTIFACT_BYTES, budget)
                    content, expected_content = actual["content"], expected["content"]
                    if (
                        content["event_key"] != expected_content["event_key"]
                        or content["record_kind"] != expected_content["record_kind"]
                    ):
                        raise ReleaseFailure("store_identity_conflict")
                    reference = _store.record_reference(verified)
                    equal = content["selected_facts"] == expected_content["selected_facts"]
                    if not equal and content["selected_facts_sha256"] == expected_content["selected_facts_sha256"]:
                        raise ReleaseFailure("store_digest_conflict")
                    if call == "returned_created" and verified.artifact_bytes != candidate:
                        outcomes[slot] = {
                            **outcome,
                            "outcome": "conflict",
                            "local_state": "local_conflict",
                            "verified_record": reference,
                            "reason": "save_readback_mismatch",
                        }
                        stop = "save_readback_mismatch"
                    elif not equal:
                        if is_observation:
                            raise ReleaseFailure("store_digest_conflict")
                        outcomes[slot] = {
                            **outcome,
                            "outcome": "existing_different_facts",
                            "local_state": "local_verified",
                            "verified_record": reference,
                            "reason": "save_failed" if call == "raised" else None,
                        }
                        stop = "save_failed" if call == "raised" else None
                    else:
                        disposition = (
                            "created"
                            if call == "returned_created"
                            else "already_saved"
                            if call == "returned_collided"
                            else "present_after_uncertain_save"
                        )
                        outcomes[slot] = {
                            **outcome,
                            "outcome": disposition,
                            "local_state": "local_verified",
                            "verified_record": reference,
                            "reason": "save_failed" if call == "raised" else None,
                        }
                        stop = "save_failed" if call == "raised" else None
                    if not is_observation and outcomes[slot]["local_state"] == "local_verified":
                        parents[event["event_id"]] = _captured_record(verified)
                        _bind_parent(event, selected, verified, [])
                check(0)
            except ReleaseFailure as error:
                expiry = persistence.failure(error)
                if expiry is not None:
                    raise expiry from error
                check(0)
                stop = error.reason
                current = outcomes[slot]
                if current["save_call"] != "not_called":
                    invalid = stop in {
                        "store_record_invalid",
                        "store_identity_conflict",
                        "store_digest_conflict",
                        "store_parent_missing",
                        "store_parent_conflict",
                    }
                    outcomes[slot] = {
                        **current,
                        "outcome": "conflict" if invalid else "indeterminate",
                        "local_state": "local_conflict" if invalid else "local_indeterminate",
                        "verified_record": None,
                        "reason": stop,
                    }
            finally:
                ledger.finish_readback()
            persistence.record(slot, canonical_bytes(outcomes[slot], 2048, budget=budget))
            if stop is not None:
                break
    except ReleaseFailure as error:
        expiry = persistence.failure(error)
        if expiry is not None:
            if expiry is error:
                raise
            raise expiry from error
        check(0)
        stop = error.reason
    if stop is not None:
        for index, outcome in enumerate(outcomes):
            if outcome["outcome"] == "not_attempted" and outcome["save_call"] == "not_called":
                outcomes[index] = {**outcome, "reason": stop}
                persistence.record(index, canonical_bytes(outcomes[index], 2048, budget=budget))
    return events, outcomes, discovery, ledger.targeted_reads, ledger.consumed - before_bytes, stop


def _render(
    base: dict[str, Any],
    events: list[dict[str, Any]],
    outcomes: list[dict[str, Any]],
    discovery: dict[str, Any],
    targeted_reads: int,
    targeted_bytes: int,
    stop: str | None,
    completed: str,
) -> dict[str, Any]:
    # All arguments here are freshly restored from owned snapshots at final use.
    result = {**base, "events": events, "outcomes": outcomes, "discovery": discovery}
    result["clocks"] = {**base["clocks"], "completed_at": completed}
    called = [index for index, outcome in enumerate(outcomes) if outcome["save_call"] != "not_called"]
    requested = base["request"]["persist"]
    state = "not_requested" if not requested else "complete" if stop is None else "partial" if called else "not_started"
    if any(outcome["outcome"] == "indeterminate" for outcome in outcomes):
        state = "indeterminate"
    result["persistence"] = {
        "requested": requested,
        "state": state,
        "planned_slots": len(outcomes),
        "attempted_calls": len(called),
        "last_attempted_slot": called[-1] if called else None,
        "outcome_counts": {name: sum(outcome["outcome"] == name for outcome in outcomes) for name in _OUTCOMES},
        "stop_reason": stop,
        "mirror_outcome": "unobserved",
    }
    result["counters"] = {
        **base["counters"],
        "targeted_record_reads": targeted_reads,
        "targeted_raw_bytes_observed": targeted_bytes,
        "total_store_raw_bytes_observed": discovery["raw_file_bytes_observed"] + targeted_bytes,
    }
    result["reasons"] = list(dict.fromkeys(reason for reason in (base["terminal_reason"], stop) if reason is not None))
    return result


@dataclass(frozen=True, slots=True)
class _CompletedPoll:
    _wire: bytes
    _check: Callable[[int], None]
    _persistence: _PersistenceAuthority

    def output_bytes(self) -> bytes:
        try:
            self._check(0)
            return self._wire
        except Exception as error:
            failure = self._persistence.failure(error)
            if failure is not None:
                if failure is error:
                    raise
                raise failure from error
            raise

    def result(self) -> PollResult:
        try:
            self._check(0)
            result = PollResult.model_validate_json(self._wire)
            self._check(0)
            return result
        except Exception as error:
            failure = self._persistence.failure(error)
            if failure is not None:
                raise failure from error
            raise


def _run(
    request_bytes: bytes,
    store_root: object,
    started: datetime,
    poll_id: str,
    budget: Budget,
    check: Callable[[int], None],
    persistence: _PersistenceAuthority,
) -> _CompletedPoll:
    from ._traversal import TraversalSnapshot, traverse

    try:
        traversal = traverse(request_bytes, budget=budget, started_at=started)
    except ReleaseFailure as error:
        traversal = TraversalSnapshot(request_bytes, b"[]", b"[]", 0, 0, 0, 0, None, error.reason)
    base = _base(request_bytes, traversal, started, poll_id, budget)
    base_bytes = canonical_bytes(base, RESULT_BYTES, budget=budget)
    events, discovery = base["events"], base["discovery"]
    outcomes: list[dict[str, Any]] = []
    targeted_reads = targeted_bytes = 0
    stop = traversal.reason if base["request"]["persist"] else None
    if base["request"]["persist"] and traversal.reason is None:
        events, outcomes, discovery, targeted_reads, targeted_bytes, stop = _persist(
            base, store_root, budget, check, persistence
        )
    check(0)
    state_bytes = canonical_bytes(
        {
            "events": events,
            "outcomes": outcomes,
            "discovery": discovery,
            "targeted_reads": targeted_reads,
            "targeted_bytes": targeted_bytes,
            "stop": stop,
        },
        RESULT_BYTES,
        budget=budget,
    )
    completed = _utc_now()
    utc_text(completed)
    if completed < started or (
        traversal.completed_at is not None and completed < parse_window_time(traversal.completed_at)
    ):
        raise ReleaseFailure("clock_invalid")
    wire = _seal_result(base_bytes, state_bytes, utc_text(completed), budget, check)
    return _CompletedPoll(wire, check, persistence)


@dataclass(frozen=True, slots=True)
class _PreparedPoll:
    budget: Budget
    _begin: Callable[..., _CompletedPoll]

    def begin(self, request: object, *, evidence_store_dir: object = None) -> _CompletedPoll:
        return self._begin(request, evidence_store_dir=evidence_store_dir)


def _prepare_poll_from_clock(invocation: _Invocation) -> _PreparedPoll:
    if type(invocation) is not _Invocation:
        raise ReleaseFailure("clock_invalid")
    original, started, check = invocation.take()
    utc_text(started)
    reader = invocation.budget
    lock = threading.Lock()

    def begin(request: object, *, evidence_store_dir: object = None) -> _CompletedPoll:
        if not lock.acquire(blocking=False):
            raise ReleaseFailure("invalid_request")
        check(0)
        try:
            checked = PollRequest.model_validate(request)
            captured = canonical_bytes(native_model(checked), 4096, budget=original, max_depth=8, max_values=64)
        except ValidationError:
            raise ReleaseFailure("invalid_request") from None
        check(0)
        try:
            return _run(
                captured, evidence_store_dir, started, str(uuid.uuid4()), original, check, invocation.persistence
            )
        except Exception as error:
            failure = invocation.persistence.failure(error)
            if failure is not None:
                raise failure from error
            raise

    return _PreparedPoll(reader, begin)


def _prepare_poll() -> _PreparedPoll:
    return _prepare_poll_from_clock(_capture_invocation(start_budget(), _utc_now()))


def poll_release_bytes(request: object, *, evidence_store_dir: object = None) -> bytes:
    return _prepare_poll().begin(request, evidence_store_dir=evidence_store_dir).output_bytes()


def collect_release_cadence(request: object, *, evidence_store_dir: object = None) -> PollResult:
    return _prepare_poll().begin(request, evidence_store_dir=evidence_store_dir).result()
