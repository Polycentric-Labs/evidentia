"""Focused closure controls for the three ledger review findings."""

from __future__ import annotations

from datetime import timedelta

import pytest

from ._ledger_support import NOW, diagnostics, event, reading, start


@pytest.mark.parametrize(
    "options,rows,continuation,code",
    [
        ({"max_items": 1}, 2, False, "item_limit"),
        ({"max_items": 1}, 1, True, "item_limit"),
        ({"max_pages": 1}, 0, True, "page_limit"),
    ],
)
def test_stopping_limit_prevents_further_attempts_and_admission(options, rows, continuation, code):
    ctx, _, _clock = start(**options)
    read = reading(ctx)
    assert read.admit_page([event(str(i)) for i in range(rows)], continuation=continuation) is False
    before = (read.pages, read.attempts, read.scanned, ctx.slots_used)
    with pytest.raises(ValueError, match="invalid_reading"):
        read.note_attempt()
    with pytest.raises(ValueError, match="invalid_reading"):
        read.admit_page([event("extra")], continuation=False)
    assert (read.pages, read.attempts, read.scanned, ctx.slots_used) == before
    result = read.finish_source()
    assert result.capability.state == "partial"
    assert diagnostics(result.capability) == {(code, None): 1}


def test_unfinished_empty_enumeration_cannot_hide_behind_warning():
    ctx, _, _clock = start()
    read = reading(ctx)
    read.admit_page([], continuation=True)
    read.add_diagnostic("source_retention_limited")
    result = read.finish_source()
    assert result.capability.state == "partial"
    assert diagnostics(result.capability) == {
        ("source_retention_limited", None): 1,
        ("continuation_invalid", None): 1,
    }


def test_handled_later_failure_keeps_its_specific_diagnostic():
    ctx, _, _clock = start()
    read = reading(ctx)
    read.admit_page([], continuation=True)
    read.add_diagnostic("connection_failed")
    result = read.finish_source()
    assert result.capability.state == "partial"
    assert diagnostics(result.capability) == {("connection_failed", None): 1}


def test_repeated_failed_finalization_does_not_commit_derived_diagnostics():
    ctx, _, clock = start()
    read = reading(ctx)
    read.admit_page([event("future", "2026-01-31T00:00:00.000000000001Z")], continuation=False)
    read.add_diagnostic("source_retention_limited", count=3)
    before = dict(read._diagnostics)
    for _ in range(2):
        clock.wall = NOW - timedelta(seconds=1)
        with pytest.raises(ValueError):
            read.finish_source()
        assert read._diagnostics == before
    clock.wall = NOW
    result = read.finish_source()
    assert diagnostics(result.capability) == {
        ("source_retention_limited", None): 3,
        ("future_timestamp", None): 1,
    }
    assert read._diagnostics == before


@pytest.mark.parametrize("value", [True, "1", None, float("nan"), float("inf"), -float("inf"), 10**400])
def test_invalid_clock_sample_does_not_replace_prior_sample(value):
    ctx, _, clock = start()
    read = reading(ctx)
    clock.value = 0.5
    assert read.remaining() == 59.5
    clock.value = value
    with pytest.raises(ValueError, match=r"^internal_error$"):
        read.remaining()
    clock.value = 0.5
    assert read.remaining() == 59.5


def test_backwards_clock_is_rejected_without_mutating_prior_sample():
    ctx, _, clock = start()
    read = reading(ctx)
    clock.value = 0.5
    assert read.remaining() == 59.5
    clock.value = 0.25
    with pytest.raises(ValueError, match=r"^internal_error$"):
        read.remaining()
    clock.value = 0.75
    assert read.remaining() == 59.25
