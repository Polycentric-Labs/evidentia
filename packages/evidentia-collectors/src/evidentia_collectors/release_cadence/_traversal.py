"""Atomic admission of the pinned public release page profile."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from evidentia_core.release_cadence._contracts import PageLedger, PollRequest, native_model
from evidentia_core.release_cadence._json import canonical_bytes, preflight
from evidentia_core.release_cadence._limits import (
    MAX_PAGES,
    MAX_ROWS,
    PAGE_BYTES,
    RESULT_BYTES,
    SELECTED_BYTES,
    SELECTED_TOTAL_BYTES,
    Budget,
    ReleaseFailure,
    integer,
)
from evidentia_core.release_cadence._source import canonical_repository, selected_facts
from evidentia_core.release_cadence._time import utc_text

from ._http import EntityTotals, HttpAttempt, link_relations


def _utc_now() -> datetime:
    return datetime.now(UTC)


def reserved_result_bytes(selected: int, rows: int, events: int) -> int:
    integer(selected, 0, SELECTED_TOTAL_BYTES)
    integer(rows, 0, MAX_ROWS)
    integer(events, 0, rows)
    # Includes row wrappers, all ten attempt ledgers, complete envelope and both
    # 2048-byte outcome alternatives for each possible source event.
    return selected + rows * 2048 + 10 * 12288 + events * 2048 + events * 2 * 2048 + 65536


@dataclass(frozen=True, slots=True)
class TraversalSnapshot:
    request_bytes: bytes
    occurrences_bytes: bytes
    pages_bytes: bytes
    selected_bytes: int
    raw_bytes: int
    decoded_bytes: int
    attempts: int
    completed_at: str | None
    reason: str | None


def _page(number: int) -> dict[str, object]:
    return {
        "page_index": number - 1,
        "page_ordinal": number,
        "page_number": number,
        "http_status": None,
        "retrieved_at": None,
        "raw_bytes_observed": 0,
        "decoded_bytes_observed": 0,
        "raw_body_complete": False,
        "decoded_body_complete": False,
        "raw_body_sha256": None,
        "decoded_body_sha256": None,
        "link_state": "unavailable",
        "link_values_sha256": None,
        "first_page": None,
        "previous_page": None,
        "next_page": None,
        "last_page": None,
        "json_value_key_occurrences": None,
        "json_depth_observed": None,
        "decoded_row_count": None,
        "admitted": False,
        "row_start": None,
        "row_count": 0,
        "reason": None,
    }


def _copy_attempt(ledger: dict[str, object], attempt: HttpAttempt) -> None:
    ledger.update(
        {
            "http_status": attempt.status_code,
            "raw_bytes_observed": attempt.raw,
            "decoded_bytes_observed": attempt.decoded,
            "raw_body_complete": attempt.raw_body_complete,
            "decoded_body_complete": attempt.body_complete,
            "raw_body_sha256": attempt.raw_body_sha256,
            "decoded_body_sha256": attempt.body_sha256,
        }
    )


def _links(ledger: dict[str, object], attempt: HttpAttempt, owner: str, repository: str, page: int) -> int | None:
    if not attempt.links_available:
        raise ReleaseFailure("invalid_response")
    values = attempt.links
    if (
        type(values) is not tuple
        or len(values) > 4
        or any(type(value) is not bytes for value in values)
        or sum(map(len, values)) > 8192
    ):
        ledger["link_state"] = "invalid"
        raise ReleaseFailure("unsupported_link")
    if all(value.isascii() for value in values):
        encoded = canonical_bytes([value.decode("ascii") for value in values], 65536)
        ledger["link_values_sha256"] = hashlib.sha256(encoded).hexdigest()
    try:
        relations = link_relations(values, owner, repository, page)
    except ReleaseFailure:
        ledger["link_state"] = "invalid"
        raise
    ledger["link_state"] = "valid" if values else "absent"
    for source, target in (
        ("first", "first_page"),
        ("prev", "previous_page"),
        ("next", "next_page"),
        ("last", "last_page"),
    ):
        ledger[target] = relations.get(source)
    return relations.get("next")


def traverse(request_bytes: bytes, *, budget: Budget, started_at: datetime) -> TraversalSnapshot:
    """Return immutable admitted source and attempt ledgers under the original clock."""
    if type(request_bytes) is not bytes or type(budget) is not Budget:
        raise ReleaseFailure()
    utc_text(started_at)
    deadline = budget.deadline
    if type(deadline) is not float:
        raise ReleaseFailure("clock_invalid")
    work = Budget(deadline - 15)

    def check() -> None:
        if (
            type(budget.deadline) is not float
            or budget.deadline != deadline
            or type(work.deadline) is not float
            or work.deadline != deadline - 15
        ):
            raise ReleaseFailure("clock_invalid")
        work.check()

    check()
    request = native_model(PollRequest.model_validate_json(request_bytes))
    if canonical_bytes(request, 4096, budget=work) != request_bytes:
        raise ReleaseFailure()
    owner, repository = canonical_repository(request["owner"], request["repository"])
    occurrences: list[dict[str, object]] = []
    ledgers: list[dict[str, object]] = []
    seen: dict[int, bytes] = {}
    selected_size = 0
    totals = EntityTotals()
    completed: str | None = None
    terminal: str | None = None
    latest = started_at
    for number in range(1, MAX_PAGES + 1):
        ledger = _page(number)
        attempt = HttpAttempt()
        following: int | None = None
        try:
            check()
            body = attempt.fetch(owner, repository, number, budget=budget, totals=totals)
            _copy_attempt(ledger, attempt)
            check()
            receipt = _utc_now()
            receipt_text = utc_text(receipt)
            if receipt < latest:
                raise ReleaseFailure("clock_invalid")
            latest = receipt
            ledger["retrieved_at"] = receipt_text
            following = _links(ledger, attempt, owner, repository, number)
            stats = preflight(body, PAGE_BYTES, budget=work)
            ledger["json_value_key_occurrences"] = stats.values
            ledger["json_depth_observed"] = stats.depth
            native = json.loads(body)
            check()
            if type(native) is not list:
                raise ReleaseFailure("source_field")
            ledger["decoded_row_count"] = len(native)
            if len(native) > 100:
                raise ReleaseFailure("row_limit")
            if len(occurrences) + len(native) > MAX_ROWS:
                raise ReleaseFailure("row_limit")
            candidate: list[dict[str, object]] = []
            additions: dict[int, bytes] = {}
            added_size = 0
            for position, source in enumerate(native):
                check()
                selected = selected_facts(source, budget=work)
                encoded = canonical_bytes(selected, SELECTED_BYTES, budget=work)
                added_size += len(encoded)
                if selected_size + added_size > SELECTED_TOTAL_BYTES:
                    raise ReleaseFailure("selected_limit")
                release_id = cast(int, selected["id"])
                previous = seen.get(release_id, additions.get(release_id))
                if previous is not None and previous != encoded:
                    raise ReleaseFailure("source_conflict")
                additions[release_id] = encoded
                candidate.append({"page_index": number - 1, "record_index": position, "selected": selected})
            count = len(set(seen) | set(additions))
            if (
                reserved_result_bytes(selected_size + added_size, len(occurrences) + len(candidate), count)
                > RESULT_BYTES
            ):
                raise ReleaseFailure("result_limit")
            check()
            ledger.update({"admitted": True, "row_start": len(occurrences), "row_count": len(candidate)})
            if following is not None and number == MAX_PAGES:
                ledger["reason"] = "page_limit"
            PageLedger.model_validate(ledger)
            canonical_bytes(ledger, 12288, budget=work)
            check()
            occurrences.extend(candidate)
            seen.update(additions)
            selected_size += added_size
            if following is None:
                finished = _utc_now()
                utc_text(finished)
                if finished < latest:
                    raise ReleaseFailure("clock_invalid")
                check()
                completed = utc_text(finished)
        except ReleaseFailure as error:
            terminal = error.reason
            ledger["reason"] = terminal
            # Page rows were admitted only after every page gate. A later clock
            # failure keeps their exact span but cannot establish completion.
        finally:
            _copy_attempt(ledger, attempt)
        ledgers.append(ledger)
        if terminal is not None or completed is not None:
            break
        if number == MAX_PAGES:
            terminal = "page_limit"
            break
    # Finalization may use the reserved part of the same original clock. These
    # byte snapshots become the collector's retained source authority.
    if type(budget.deadline) is not float or budget.deadline != deadline:
        raise ReleaseFailure("clock_invalid")
    budget.check()
    page_bytes = canonical_bytes(ledgers, 10 * 12288 + 16, budget=budget)
    occurrence_bytes = canonical_bytes(occurrences, RESULT_BYTES, budget=budget)
    budget.check()
    return TraversalSnapshot(
        request_bytes,
        occurrence_bytes,
        page_bytes,
        selected_size,
        totals.raw,
        totals.decoded,
        len(ledgers),
        completed,
        terminal,
    )
