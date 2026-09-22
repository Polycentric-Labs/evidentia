"""Atomic page admission and fixed visible traversal controls."""

from datetime import UTC, datetime

import pytest
from evidentia_collectors.release_cadence import _traversal
from evidentia_core.release_cadence._json import load_json
from evidentia_core.release_cadence._limits import ReleaseFailure, start_budget

from ._helpers import encoded, pages, request_bytes, row
from .test_http import link

NOW = datetime(2001, 1, 1, tzinfo=UTC)


def run(monkeypatch, entries, **request_changes):
    calls = pages(monkeypatch, _traversal, entries)
    monkeypatch.setattr(_traversal, "_utc_now", lambda: NOW)
    snapshot = _traversal.traverse(request_bytes(**request_changes), budget=start_budget(), started_at=NOW)
    return snapshot, calls, load_json(snapshot.occurrences_bytes, 16_777_216), load_json(snapshot.pages_bytes, 131_072)


def test_short_and_empty_pages_follow_next(monkeypatch):
    entries = [(b"[]", (link("2"),)), (encoded([row()]), ())]
    snapshot, calls, rows, ledger = run(monkeypatch, entries)
    assert [c[2] for c in calls] == [1, 2]
    assert snapshot.reason is None and snapshot.completed_at == "2001-01-01T00:00:00.000000Z"
    assert len(rows) == 1 and rows[0]["page_index"] == 1 and rows[0]["record_index"] == 0
    assert [(p["row_start"], p["row_count"], p["admitted"]) for p in ledger] == [(0, 0, True), (0, 1, True)]
    assert ledger[0]["next_page"] == 2 and ledger[1]["link_state"] == "absent"


@pytest.mark.parametrize("change", [{"name": ""}, {"draft": True}, {"updated_at": None}, {"immutable": False}])
def test_unequal_duplicate_rejects_whole_page_before_channel(monkeypatch, change):
    entries = [(encoded([row()]), (link("2"),)), (encoded([row(102), row(**change)]), ())]
    snapshot, calls, rows, ledger = run(monkeypatch, entries)
    assert snapshot.reason == "source_conflict" and snapshot.completed_at is None
    assert len(rows) == 1 and len(calls) == 2
    assert not ledger[1]["admitted"] and ledger[1]["row_start"] is None
    assert ledger[1]["raw_body_complete"] and ledger[1]["decoded_body_sha256"] is not None


def test_identical_repeats_keep_positions_and_charge_every_occurrence(monkeypatch):
    snapshot, _, rows, ledger = run(monkeypatch, [(encoded([row(), row()]), ())])
    assert snapshot.reason is None and len(rows) == 2
    assert [r["record_index"] for r in rows] == [0, 1]
    assert rows[0]["selected"] == rows[1]["selected"]
    assert snapshot.selected_bytes % 2 == 0 and ledger[0]["row_count"] == 2


@pytest.mark.parametrize(
    "raw,reason",
    [
        (b'{"x":1}', "source_field"),
        (b'[{"x":1,"x":2}]', "json_syntax"),
        (b"[] []", "json_syntax"),
        (encoded([row()] * 101), "row_limit"),
        (encoded([row(id=1.0)]), "source_field"),
        (encoded([row(), {"id": 2}]), "source_field"),
    ],
)
def test_invalid_page_is_not_partially_salvaged(monkeypatch, raw, reason):
    snapshot, _, rows, ledger = run(monkeypatch, [(raw, ())])
    assert snapshot.reason == reason and rows == [] and snapshot.completed_at is None
    assert len(ledger) == 1 and not ledger[0]["admitted"]
    assert ledger[0]["raw_body_complete"] and ledger[0]["decoded_body_complete"]


def test_unknown_duplicate_key_is_not_ignored(monkeypatch):
    raw = encoded([row(unknown={"x": 1})]).replace(b'"x":1', b'"x":1,"x":2')
    snapshot, _, rows, _ = run(monkeypatch, [(raw, ())])
    assert rows == [] and snapshot.reason == "json_syntax"


def test_invalid_link_keeps_complete_body_but_no_rows(monkeypatch):
    snapshot, _, rows, ledger = run(monkeypatch, [(encoded([row()]), (link("3"),))])
    assert snapshot.reason == "unsupported_link" and rows == []
    assert ledger[0]["link_state"] == "invalid"
    assert ledger[0]["link_values_sha256"] is not None
    assert all(ledger[0][key] is None for key in ("first_page", "previous_page", "next_page", "last_page"))


def test_page_ten_next_is_admitted_then_stops_without_eleven(monkeypatch):
    entries = [(b"[]", (link(str(p + 1)),)) for p in range(1, 11)]
    snapshot, calls, rows, ledger = run(monkeypatch, entries)
    assert len(calls) == len(ledger) == 10 and rows == []
    assert all(p["admitted"] for p in ledger)
    assert ledger[-1]["reason"] == "page_limit"
    assert snapshot.reason == "page_limit" and snapshot.completed_at is None


def test_transport_failure_keeps_prior_admitted_pages(monkeypatch):
    snapshot, _, rows, ledger = run(
        monkeypatch,
        [
            (encoded([row()]), (link("2"),)),
            ReleaseFailure("upstream_not_found"),
        ],
    )
    assert snapshot.reason == "upstream_not_found" and len(rows) == 1
    assert ledger[1]["retrieved_at"] is None and not ledger[1]["raw_body_complete"]


def test_late_cancellation_is_same_object(monkeypatch):
    cancellation = KeyboardInterrupt()
    pages(monkeypatch, _traversal, [(b"[]", (link("2"),)), cancellation])
    monkeypatch.setattr(_traversal, "_utc_now", lambda: NOW)
    with pytest.raises(KeyboardInterrupt) as found:
        _traversal.traverse(request_bytes(), budget=start_budget(), started_at=NOW)
    assert found.value is cancellation


def test_backward_receipt_clock_refuses_without_synthesized_completion(monkeypatch):
    pages(monkeypatch, _traversal, [(b"[]", ())])
    monkeypatch.setattr(_traversal, "_utc_now", lambda: datetime(2000, 1, 1, tzinfo=UTC))
    snapshot = _traversal.traverse(request_bytes(), budget=start_budget(), started_at=NOW)
    assert snapshot.reason == "clock_invalid" and snapshot.completed_at is None
    ledger = load_json(snapshot.pages_bytes, 131_072)
    assert ledger[0]["retrieved_at"] is None and not ledger[0]["admitted"]


def test_capacity_reservation_uses_two_2048_byte_outcomes():
    assert _traversal.reserved_result_bytes(8_388_608, 1000, 1000) == 16_769_024
    assert _traversal.reserved_result_bytes(8_388_608, 1000, 1000) < 16_777_216


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"name": 42}, "source_field"),
        ({"published_at": "x" * 129}, "source_field"),
        ({"name": "x" * 16350}, "selected_limit"),
    ],
)
def test_selected_source_refusal_keeps_typed_partial_page(monkeypatch, change, reason):
    snapshot, calls, rows, ledger = run(
        monkeypatch,
        [
            (encoded([row(1)]), (link("2"),)),
            (encoded([row(2, **change)]), ()),
        ],
    )
    assert snapshot.reason == reason and snapshot.completed_at is None
    assert len(rows) == 1 and len(calls) == 2
    assert ledger[1]["reason"] == reason and ledger[1]["admitted"] is False


def test_one_row_page_with_next_is_not_terminal(monkeypatch):
    entries = [(encoded([row(1)]), (link("2"),)), (encoded([row(2)]), ())]
    snapshot, calls, rows, ledger = run(monkeypatch, entries)
    assert [call[2] for call in calls] == [1, 2]
    assert snapshot.reason is None and snapshot.completed_at == "2001-01-01T00:00:00.000000Z"
    assert [value["selected"]["id"] for value in rows] == [1, 2]
    assert [(value["page_index"], value["record_index"]) for value in rows] == [(0, 0), (1, 0)]
    assert ledger[0]["next_page"] == 2 and ledger[1]["link_state"] == "absent"


def test_terminal_third_page_keeps_first_and_previous_relations(monkeypatch):
    terminal = link("1", "first") + b", " + link("2", "prev")
    entries = [(encoded([row(1)]), (link("2"),)), (b"[]", (link("3"),)), (encoded([row(2)]), (terminal,))]
    snapshot, calls, rows, ledger = run(monkeypatch, entries)
    assert [call[2] for call in calls] == [1, 2, 3]
    assert snapshot.reason is None and snapshot.completed_at == "2001-01-01T00:00:00.000000Z"
    assert [value["selected"]["id"] for value in rows] == [1, 2]
    assert ledger[2]["first_page"] == 1 and ledger[2]["previous_page"] == 2
    assert ledger[2]["next_page"] is None and ledger[2]["last_page"] is None
    assert ledger[2]["admitted"] and ledger[2]["link_state"] == "valid"


@pytest.mark.parametrize("following", ["1", "2"])
def test_second_page_next_loop_refuses_whole_page(monkeypatch, following):
    entries = [(encoded([row(1)]), (link("2"),)), (encoded([row(2)]), (link(following),))]
    snapshot, calls, rows, ledger = run(monkeypatch, entries)
    assert snapshot.reason == "unsupported_link" and snapshot.completed_at is None
    assert len(calls) == 2 and [value["selected"]["id"] for value in rows] == [1]
    assert not ledger[1]["admitted"] and ledger[1]["row_count"] == 0
    assert ledger[1]["raw_body_complete"] and ledger[1]["link_values_sha256"] is not None


def test_101_row_second_page_preserves_only_prior_admission(monkeypatch):
    entries = [(encoded([row(1)]), (link("2"),)), (encoded([row(index) for index in range(2, 103)]), ())]
    snapshot, calls, rows, ledger = run(monkeypatch, entries)
    assert snapshot.reason == "row_limit" and snapshot.completed_at is None
    assert len(calls) == 2 and [value["selected"]["id"] for value in rows] == [1]
    assert ledger[1]["decoded_row_count"] == 101 and not ledger[1]["admitted"]


def test_prerelease_duplicate_conflict_precedes_channel_exclusion(monkeypatch):
    entries = [(encoded([row(prerelease=True)]), (link("2"),)), (encoded([row(prerelease=False)]), ())]
    snapshot, _, rows, ledger = run(monkeypatch, entries, channel="full_releases")
    assert snapshot.reason == "source_conflict" and snapshot.completed_at is None
    assert len(rows) == 1 and rows[0]["selected"]["prerelease"] is True
    assert ledger[0]["admitted"] and not ledger[1]["admitted"]
